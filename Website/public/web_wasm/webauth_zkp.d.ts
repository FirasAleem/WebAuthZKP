/* tslint:disable */
/* eslint-disable */
/**
* @param {string} client_data_json_base64
* @param {string} auth_data_base64
* @param {string} challenge_base64
* @returns {any}
*/
export function run_js(client_data_json_base64: string, auth_data_base64: string, challenge_base64: string): any;
/**
* @param {string} message_base64
* @param {string} challenge_base64
* @param {string} proof_base64
* @param {string} vk_base64
* @returns {boolean}
*/
export function verify_js(message_base64: string, challenge_base64: string, proof_base64: string, vk_base64: string): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly run_js: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
  readonly verify_js: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
