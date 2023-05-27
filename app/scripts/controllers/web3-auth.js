import { ObservableStore } from '@metamask/obs-store';

/**
 Store:
    web3Storage: {
        globalFingerprints:[
            domain: fingerprint
        ],
        signedMessages: {
            address: {
                localFingerprints: {
                    domain: fingerprint
                },
                localMessages: {
                    createdAt: {
                        address,
                        message,
                        createdAt,
                        domain,
                        web3Name,
                        fingerprint
                    }
                }
            }
        }
    }
 */

export default class Web3AuthController {

  constructor(opts = {}) {
    const initState = {
      web3Storage: {
        globalFingerprints:{},
        signedMessages: {
        }
    },
      ...opts.initState,
    };

    this.store = new ObservableStore(initState);
  }


  setMessageInfo(messageInfo){
    let { web3Storage } = this.store.getState();

    const { address, createdAt, domain, fingerprint } = messageInfo;

    if (web3Storage.signedMessages[address] == undefined){
      web3Storage.signedMessages[address] = {
        localFingerprints:{},
        localMessages:{}
      }
    }
    web3Storage.signedMessages[address].localMessages[createdAt] = messageInfo;
    web3Storage.signedMessages[address].localFingerprints[domain] = fingerprint;
    this.store.updateState({ web3Storage: web3Storage});
  }

  setGlobalFingerprint(messageInfo){
    let { web3Storage } = this.store.getState();

    const { domain, fingerprint } = messageInfo;

    // use the latest fingerprint, update global fingerprint
    web3Storage.globalFingerprints[domain] = fingerprint;

    this.store.updateState({ web3Storage: web3Storage});
  }
}