export type Category = 'credentials' | 'challenge' | 'redirect'

export interface ProviderMeta {
  name: string
  category: Category
  canBePrimary: boolean
  canStepUp: boolean
  jitProvisioning: boolean
  interactive: boolean
  multipleIdentities: boolean
}

export interface User {
  id: number
  name?: string
  display?: string
  createdAt: string
  updatedAt: string
}

export interface Identity {
  id: number
  userId: number
  provider: string
  createdAt: string
}

export type AuthMode = 'login' | 'register' | 'link'

export type Phase = 'finish' | 'challenge' | 'redirect' | 'stepup'

export type ChallengeResponse =
  | { shape: 'code'; length: number; digits: boolean }
  | { shape: 'webauthn-create'; options: any }
  | { shape: 'webauthn-get'; options: any }

export type StepResult =
  | { phase: 'finish'; token?: string; userId?: number; identityId?: number; created?: boolean }
  | { phase: 'challenge'; challengeId: string; response: ChallengeResponse; data?: any }
  | { phase: 'redirect'; url: string }
  | { phase: 'stepup'; stepupId: string; factors: { provider: string; category: Category }[] }
