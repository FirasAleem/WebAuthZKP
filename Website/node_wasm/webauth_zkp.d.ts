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
