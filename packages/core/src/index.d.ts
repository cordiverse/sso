import { Context, Service } from 'cordis';
declare module 'cordis' {
    interface Context {
        sso: Sso;
    }
    interface Events {
        'sso/auth'(event: Sso.AuthEvent): void;
    }
}
declare module 'minato' {
    interface Tables {
        user: User;
        sso_identity: Identity;
        sso_session: Session;
    }
}
export interface SsoProvider {
    name: string;
    interactive: boolean;
    autoRegister: boolean;
    resolve?(credentials: any): Promise<{
        identityId: number;
        data?: any;
    } | null>;
    register?(credentials: any): Promise<{
        data?: any;
    }>;
    getAuthUrl?(redirectUri: string, state: string): string;
    challenge?(target: any): Promise<{
        challengeId: string;
    }>;
    verify?(challengeId: string, response: string): Promise<boolean>;
}
export interface User {
    id: number;
    name?: string;
    createdAt: Date;
    updatedAt: Date;
}
export interface Identity {
    id: number;
    userId: number;
    provider: string;
    createdAt: Date;
}
export interface Session {
    token: string;
    userId: number;
    identityId: number;
    createdAt: Date;
    expiresAt: Date;
}
export interface SsoProvider {
    name: string;
    interactive: boolean;
    autoRegister: boolean;
    /** Resolve credentials to an existing identity. */
    resolve?(credentials: any): Promise<{
        identityId: number;
        data?: any;
    } | null>;
    /** Register a new identity. Provider should create its own table row using the returned identityId. */
    register?(credentials: any): Promise<{
        data?: any;
    }>;
    /** Get OAuth authorization URL. */
    getAuthUrl?(redirectUri: string, state: string): string;
    /** Initiate a challenge (e.g. send verification code). */
    challenge?(target: any): Promise<{
        challengeId: string;
    }>;
    /** Verify a challenge response. */
    verify?(challengeId: string, response: string): Promise<boolean>;
}
export declare namespace Sso {
    interface Config {
        sessionMaxAge?: number;
    }
    interface AuthEvent {
        provider: string;
        credentials: any;
        request?: any;
    }
}
export declare class Sso extends Service {
    config: Sso.Config;
    static inject: string[];
    private _providers;
    constructor(ctx: Context, config?: Sso.Config);
    register(provider: SsoProvider): () => void;
    getProviders(): SsoProvider[];
    getProvider(name: string): SsoProvider | undefined;
    createUser(provider: string): Promise<{
        user: User;
        identityId: number;
    }>;
    getUser(userId: number): Promise<User | null>;
    link(userId: number, provider: string): Promise<{
        identityId: number;
    }>;
    unlink(identityId: number): Promise<void>;
    getIdentities(userId: number): Promise<Identity[]>;
    getIdentity(identityId: number): Promise<Identity | null>;
    createSession(userId: number, identityId: number): Promise<string>;
    validateSession(token: string): Promise<User | null>;
    destroySession(token: string): Promise<void>;
    destroyUserSessions(userId: number, except?: string): Promise<void>;
}
export default Sso;
