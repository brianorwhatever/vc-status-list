/*!
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
import credentialsCtx from 'credentials-context';
import {BitstringStatusList} from './BitstringStatusList.js';
import {verifyCredential as vcVerifyCredential} from '@digitalbazaar/vc';
// import statusListCtx from
//   '@digitalbazaar/vc-status-list-context';

const VC_V1_CONTEXT_URL = credentialsCtx.constants.CREDENTIALS_CONTEXT_V1_URL;
// const BSL_V1_CONTEXT_URL = statusListCtx.constants.CONTEXT_URL_V1;
const BSL_V1_CONTEXT_URL = 'https://w3.org/ns/credentials/status';
const VC_V2_CONTEXT_URL = 'https://w3.org/ns/credentials/v2';

export {BitstringStatusList};

export async function createList({length}) {
  return new BitstringStatusList({length});
}

export async function decodeList({encodedList}) {
  console.log(BitstringStatusList.decode({encodedList}));
  return BitstringStatusList.decode({encodedList});
}

/**
 * Creates a BitstringStatusList Credential.
 *
 * @param {object} options - Options to use.
 * @param {string} options.id - The id for StatusList Credential.
 * @param {BitstringStatusList} options.list - Instance of BitstringStatusList.
 * @param {string} options.statusPurpose - The purpose of the status entry.
 *
 * @returns {object} The resulting `StatusList Credential`.
 */
export async function createCredential({id, list, statusPurpose}) {
  console.log('createCredential');
  if(!(id && typeof id === 'string')) {
    throw new TypeError('"id" is required.');
  }
  if(!(list && typeof list.encode === 'function')) {
    throw new TypeError('"list" is required.');
  }
  if(!(statusPurpose && typeof statusPurpose === 'string')) {
    throw new TypeError('"statusPurpose" is required.');
  }
  const encodedList = await list.encode();
  return {
    '@context': [VC_V2_CONTEXT_URL],
    id,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    credentialSubject: {
      id: `${id}#list`,
      type: 'BitstringStatusList',
      encodedList,
      statusPurpose
    }
  };
}

export async function checkStatus({
  credential,
  documentLoader,
  suite,
  verifyStatusListCredential = true,
  verifyMatchingIssuers = true
} = {}) {
  let result;
  try {
    result = await _checkStatuses({
      credential,
      documentLoader,
      suite,
      verifyStatusListCredential,
      verifyMatchingIssuers,
    });
  } catch(error) {
    result = {
      verified: false,
      error,
    };
  }
  return result;
}

export function statusTypeMatches({credential} = {}) {
  _isObject({credential});
  // check for expected contexts
  const {'@context': contexts} = credential;
  if(!Array.isArray(contexts)) {
    throw new TypeError('"@context" must be an array.');
  }
  if(contexts[0] !== VC_V1_CONTEXT_URL && contexts[0] !== VC_V2_CONTEXT_URL) {
    throw new Error(
      `The first "@context" value must be "${VC_V1_CONTEXT_URL}" or ` +
      `${VC_V2_CONTEXT_URL}.`);
  }
  const {credentialStatus} = credential;
  if(!credentialStatus) {
    // no status; no match
    return false;
  }
  if(typeof credentialStatus !== 'object') {
    // bad status
    throw new Error('"credentialStatus" is invalid.');
  }
  if(!contexts.includes(VC_V2_CONTEXT_URL) &&
     !contexts.includes(BSL_V1_CONTEXT_URL)) {
    // context not present, no match
    return false;
  }
  const credentialStatuses = _getStatuses({credential});
  return credentialStatuses.length > 0;
}

export function assertBitstringStatusListContext({credential} = {}) {
  _isObject({credential});
  // check for expected contexts
  const {'@context': contexts} = credential;
  if(!Array.isArray(contexts)) {
    throw new TypeError('"@context" must be an array.');
  }
  if(contexts[0] !== VC_V1_CONTEXT_URL && contexts[0] !== VC_V2_CONTEXT_URL) {
    throw new Error(
      `The first "@context" value must be "${VC_V1_CONTEXT_URL}" or `
      `${VC_V2_CONTEXT_URL}.`);
  }
  if(!contexts.includes(BSL_V1_CONTEXT_URL) &&
     !contexts.includes(VC_V2_CONTEXT_URL)) {
    throw new TypeError(`"@context" must include "${BSL_V1_CONTEXT_URL}".`);
  }
}

/**
 * Gets the `credentialStatus` of a credential based on its status purpose
 * (`statusPurpose`).
 *
 * @param {object} options - Options to use.
 * @param {object} options.credential - A VC.
 * @param {'revocation'|'suspension'} options.statusPurpose - A
 *   `statusPurpose`.
 *
 * @throws If the `credentialStatus` is invalid or missing.
 *
 * @returns {object} The resulting `credentialStatus`.
 */
export function getCredentialStatus({credential, statusPurpose} = {}) {
  _isObject({credential});
  assertBitstringStatusListContext({credential});
  if(!(statusPurpose && typeof statusPurpose === 'string')) {
    throw new TypeError('"statusPurpose" must be a string.');
  }
  // get and validate status
  if(!(credential.credentialStatus &&
    typeof credential.credentialStatus === 'object')) {
    throw new Error('"credentialStatus" is missing or invalid.');
  }
  const credentialStatuses = _getStatuses({credential});
  if(credentialStatuses.length === 0) {
    throw new Error('"credentialStatus" with type "BitstringStatusListEntry" ' +
    `and status purpose "${statusPurpose}" not found.`);
  }
  const result = credentialStatuses.filter(
    credentialStatus => _validateStatus({credentialStatus})).find(
    // check for matching `statusPurpose`
    cs => cs.statusPurpose === statusPurpose);
  if(!result) {
    throw new Error('"credentialStatus" with type "BitstringStatusListEntry" ' +
    `and status purpose "${statusPurpose}" not found.`);
  }
  return result;
}

async function _checkStatus({
  credential,
  credentialStatus,
  verifyStatusListCredential,
  verifyMatchingIssuers,
  suite,
  documentLoader
}) {
  // get BSL position
  const {statusListIndex} = credentialStatus;
  const index = parseInt(statusListIndex, 10);
  // retrieve SL VC
  let bslCredential;
  try {
    ({document: bslCredential} = await documentLoader(
      credentialStatus.statusListCredential));
  } catch(e) {
    const err = new Error(
      'Could not load "BitstringStatusListCredential"; ' +
      `reason: ${e.message}`);
    err.cause = e;
    throw err;
  }
  const {statusPurpose: credentialStatusPurpose} = credentialStatus;
  const {statusPurpose: bslCredentialStatusPurpose} =
  bslCredential.credentialSubject;
  if(bslCredentialStatusPurpose !== credentialStatusPurpose) {
    throw new Error(
      `The status purpose "${bslCredentialStatusPurpose}" of the status ` +
      `list credential does not match the status purpose ` +
      `"${credentialStatusPurpose}" in the credential.`);
  }
  // verify SL VC
  if(verifyStatusListCredential) {
    const verifyResult = await vcVerifyCredential({
      credential: bslCredential,
      suite,
      documentLoader
    });
    if(!verifyResult.verified) {
      const {error: e} = verifyResult;
      let msg = '"BitstringStatusListCredential" not verified';
      if(e) {
        msg += `; reason: ${e.message}`;
      } else {
        msg += '.';
      }
      const err = new Error(msg);
      if(e) {
        err.cause = verifyResult.error;
      }
      throw err;
    }
  }

  // ensure that the issuer of the verifiable credential matches
  // the issuer of the statusListCredential
  if(verifyMatchingIssuers) {
    // covers both the URI and object cases
    const credentialIssuer =
      typeof credential.issuer === 'object' ?
        credential.issuer.id : credential.issuer;
    const statusListCredentialIssuer =
      typeof bslCredential.issuer === 'object' ?
        bslCredential.issuer.id : bslCredential.issuer;

    if(!(credentialIssuer && statusListCredentialIssuer) ||
      (credentialIssuer !== statusListCredentialIssuer)) {
      throw new Error(
        'Issuers of the status list credential and verifiable ' +
        'credential do not match.');
    }
  }
  if(!bslCredential.type.includes('BitstringStatusListCredential')) {
    throw new Error('Status list credential type must include ' +
      '"BitstringStatusListCredential".');
  }
  console.log(bslCredential);

  // get JSON StatusList
  const {credentialSubject: bsl} = bslCredential;
  console.log(bslCredential);

  if(bsl.type !== 'BitstringStatusList') {
    throw new Error('Status list type must be "BitstringStatusList".');
  }

  // decode list from BSL VC
  const {encodedList} = bsl;
  const list = await decodeList({encodedList});

  // check VC's SL index for the status
  const verified = !list.getStatus(index);
  return {verified, credentialStatus};
}

async function _checkStatuses({
  credential,
  documentLoader,
  suite,
  verifyStatusListCredential,
  verifyMatchingIssuers
}) {
  _isObject({credential});
  if(typeof documentLoader !== 'function') {
    throw new TypeError('"documentLoader" must be a function.');
  }
  if(verifyStatusListCredential && !(suite && (
    isArrayOfObjects(suite) ||
    (!Array.isArray(suite) && typeof suite === 'object')))) {
    throw new TypeError('"suite" must be an object or an array of objects.');
  }
  const credentialStatuses = _getStatuses({credential});
  if(credentialStatuses.length === 0) {
    throw new Error(
      '"credentialStatus.type" must be "BitstringStatusListEntry".');
  }
  credentialStatuses.forEach(
    credentialStatus => _validateStatus({credentialStatus}));
  const results = await Promise.all(credentialStatuses.map(
    credentialStatus => _checkStatus({
      credential,
      credentialStatus,
      suite,
      documentLoader,
      verifyStatusListCredential,
      verifyMatchingIssuers
    })));
  const verified = results.every(
    ({verified = false} = {}) => verified === true);
  return {verified, results};
}

/**
 * Takes in a credentialStatus an ensures it meets the
 * normative statements from the Bitstring Status List spec.
 *
 * @see https://w3c.github.io/vc-bitstring-status-list/
 *
 * @param {object} options - Options to use.
 * @param {object} options.credentialStatus - A credentialStatus.
 *
 * @throws - An error if the credentialStatus is non-normative.
 *
 * @returns {object} A credentialStatus.
 */
function _validateStatus({credentialStatus}) {
  if(credentialStatus.type !== 'BitstringStatusListEntry') {
    throw new Error(
      '"credentialStatus.type" must be "BitstringStatusListEntry".');
  }
  if(typeof credentialStatus.statusPurpose !== 'string') {
    throw new TypeError(
      '"credentialStatus.statusPurpose" must be a string.');
  }
  if(typeof credentialStatus.id !== 'string') {
    throw new TypeError(
      '"credentialStatus.id" must be a string.');
  }
  if(typeof credentialStatus.statusListCredential !== 'string') {
    throw new TypeError(
      '"credentialStatus.statusListCredential" must be a string.');
  }
  const index = parseInt(credentialStatus.statusListIndex, 10);
  if(isNaN(index)) {
    throw new TypeError('"statusListIndex" must be an integer.');
  }
  if(credentialStatus.id === credentialStatus.statusListCredential) {
    throw new Error('"credentialStatus.id" must not be ' +
      '"credentialStatus.statusListCredential".');
  }
  return credentialStatus;
}

/**
 * Checks if a credential is not falsey and an object.
 *
 * @param {object} options - Options to use.
 * @param {object} [options.credential] - A potential VC.
 *
 * @throws - Throws if the credential is falsey or not an object.
 *
 * @returns {undefined}
 */
function _isObject({credential}) {
  if(!(credential && typeof credential === 'object')) {
    throw new TypeError('"credential" must be an object.');
  }
}

/**
 * Gets the statuses of a credential.
 *
 * @param {object} options - Options to use.
 * @param {object} options.credential - A VC with a credentialStatus.
 *
 * @returns {Array<object>} An array of statuses with type
 *   "BitstringStatusListEntry" or an empty array if there are no matching
 *   types.
 */
function _getStatuses({credential}) {
  const {credentialStatus} = credential;
  if(Array.isArray(credentialStatus)) {
    return credentialStatus.filter(cs => cs.type === 'BittringStatusListEntry');
  }
  if(credentialStatus && credentialStatus.type === 'BitstringStatusListEntry') {
    return [credentialStatus];
  }
  return [];
}

function isArrayOfObjects(x) {
  return Array.isArray(x) && x.length > 0 &&
    x.every(x => x && typeof x === 'object');
}
