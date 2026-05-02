import { invoke } from "@tauri-apps/api/core";

export type VpnProtocol =
  | "vless"
  | "vmess"
  | "trojan"
  | "shadowsocks"
  | "wire-guard"
  | "hysteria"
  | "hysteria2"
  | "tuic"
  | "tun"
  | "mixed"
  | "socks"
  | "http"
  | "olc-rtc";

export type TransportKind = "tcp" | "web-socket" | "grpc" | "http-upgrade" | "xhttp" | "quic";
export type RouteMode = "global" | "rule";
export type DnsStrategy = "ipv4-only" | "ipv6-only" | "prefer-ipv4" | "prefer-ipv6";
export type ConnectionPhase = "disconnected" | "connecting" | "connected" | "disconnecting" | "failed";

export interface AuthOptions {
  uuid?: string;
  password?: string;
  method?: string;
  username?: string;
}

export interface Transport {
  kind: TransportKind;
  path?: string;
  host?: string;
  serviceName?: string;
  headers?: Record<string, string>;
}

export interface TlsOptions {
  enabled: boolean;
  serverName?: string;
  alpn?: string[];
  insecure?: boolean;
  fingerprint?: string;
}

export interface RealityOptions {
  publicKey: string;
  shortId?: string;
  spiderX?: string;
}

export interface WireGuardOptions {
  privateKey: string;
  peerPublicKey?: string;
  preSharedKey?: string;
  localAddress?: string[];
  reserved?: number[];
}

export interface VpnProfile {
  id: string;
  name: string;
  protocol: VpnProtocol;
  server: string;
  port: number;
  auth: AuthOptions;
  transport?: Transport;
  tls?: TlsOptions;
  reality?: RealityOptions;
  wireguard?: WireGuardOptions;
  extra?: Record<string, unknown>;
}

export interface DnsOptions {
  strategy: DnsStrategy;
  servers: string[];
}

export interface ConnectOptions {
  profile: VpnProfile;
  routeMode?: RouteMode;
  dns?: DnsOptions;
  killSwitch?: boolean;
}

export interface ImportedServer {
  profile: VpnProfile;
  warnings: string[];
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export interface ProtocolInfo {
  protocol: VpnProtocol;
  displayName: string;
  supportedOn: string[];
  uriSchemes: string[];
}

export interface TrafficStats {
  uploadedBytes: number;
  downloadedBytes: number;
}

export interface ConnectionStatus {
  phase: ConnectionPhase;
  activeProfileId?: string;
  message?: string;
  stats: TrafficStats;
}

export async function connect(options: ConnectOptions): Promise<ConnectionStatus> {
  return invoke("plugin:vpn|connect", { options });
}

export async function disconnect(): Promise<ConnectionStatus> {
  return invoke("plugin:vpn|disconnect");
}

export async function status(): Promise<ConnectionStatus> {
  return invoke("plugin:vpn|status");
}

export async function importServer(input: string): Promise<ImportedServer> {
  return invoke("plugin:vpn|import_server", { input });
}

export async function validateProfile(profile: VpnProfile): Promise<ValidationResult> {
  return invoke("plugin:vpn|validate_profile", { profile });
}

export async function listProtocols(): Promise<ProtocolInfo[]> {
  return invoke("plugin:vpn|list_protocols");
}
