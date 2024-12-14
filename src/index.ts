import { EventPayloadMap, WebhookEventName } from '@octokit/webhooks-types/schema'
import { Context, Schema } from 'koishi'
import {} from '@koishijs/plugin-server'
import {} from 'koishi-plugin-event-server'
import { createHmac } from 'node:crypto'

type ActionName<E extends WebhookEventName> =
  | EventPayloadMap[E] extends { action: infer A }
  ? string extends A ? never : A
  : never

export type WebhookEventNameWithAction = keyof {
  [E in WebhookEventName as E | `${E}/${ActionName<E>}`]: never
}

export type Payload<T extends WebhookEventNameWithAction> = T extends `${infer E}/${infer A}`
  ? EventPayloadMap[E & WebhookEventName] & { action: A }
  : EventPayloadMap[T & WebhookEventName]

type WebhookEventMap = {
  [E in WebhookEventNameWithAction as `github/${E}`]: (payload: Payload<E>) => void
}

declare module 'koishi' {
  interface Events extends WebhookEventMap {}
}

export const name = 'github-webhook'

export const inject = ['server']

export interface Webhook {
  id?: number
  repo: string
  secret: string
}

export const Webhook: Schema<Webhook> = Schema.object({
  id: Schema.number(),
  repo: Schema.string().required(),
  secret: Schema.string().required(),
})

export interface Config {
  path: string
  webhooks: Webhook[]
}

export const Config: Schema<Config> = Schema.object({
  path: Schema.string().default('/github/webhook'),
  webhooks: Schema.array(Webhook).required(),
})

function safeParse(source: string) {
  try {
    return JSON.parse(source)
  } catch {}
}

export function apply(ctx: Context, config: Config) {
  ctx.inject(['eventServer'], (ctx) => {
    ctx.eventServer.register('github/*')
  })

  ctx.server.post(config.path, async (koa) => {
    const event = koa.headers['x-github-event'].toString()
    const signature = koa.headers['x-hub-signature-256']
    const webhookId = +koa.headers['x-github-hook-id']
    const payload = safeParse(koa.request.body.payload)
    if (!payload) return koa.status = 400
    ctx.logger.debug('received %s for %s', event, payload.repository.full_name)
    const webhook = config.webhooks.find(webhook => {
      if (webhook.id !== undefined && webhook.id !== webhookId) return false
      return webhook.repo === payload.repository.full_name
    })
    if (!webhook) return koa.status = 404
    const raw = koa.request.body[Symbol.for('unparsedBody')]
    if (signature !== `sha256=${createHmac('sha256', webhook.secret).update(raw).digest('hex')}`) {
      return koa.status = 403
    }
    ctx.emit(`github/${event}`, payload)
    if (payload.action) {
      ctx.emit(`github/${event}/${payload.action}`, payload)
    }
    koa.status = 200
  })
}
