

/**
 * Web3 Sign-in:
 * Message -(User Sign)-> Signature -(Server Verify)-> Token
 */

/**
 * Each message must replace address with '_address_'.
 * A message may not replace nonce with '_nonce_'.
 * const placeholders = ['_nonce_', '_address_']
 */

/**
 * Generate a fingerprint of a domain's messages.
 * We split a message into words, and replace some mutable words with placeholders.
 * If messageList.length > 1, we can infer that mutable words in these messages.
 * If messageList.length == 1, we directly return the split words.
 *
 * @param {Any} messageList
 *      Input a message (string) or a fingerprint (array)
 *
 * @returns {Array} fingerprint
 *     The fingerprint is a list of words in message that replace some mutable words with placeholders.
 *
 */
function generateFingerprint (messageList) {
  if (messageList.length == 0) {
      throw new Error('Message list is empty!')
  }

  let messages_words = messageList.map(message =>{
      if(typeof message == 'string'){
          // Replace address with '_address_'
          message = message.replace(/0x[a-fA-F0-9]{40}/g, '_address_')

          // Split message into words
          let words = message.split(/(\s+)/)

          return words
      }else if(Array.isArray(message)){
          return message
      }else{
          throw new Error('Message must be a string or a list of words!')
      }
  })


  // Split each message into words
  // \s: match any whitespace character (equal to [\r\n\t\f\v ])
  //let messages_words = messageList.map(message => message.split(/(\s+)/)) // retain whitespace
  //let messages_words = messageList.map(message => message.split(/\s+/))

  if (messages_words.length == 1) {
      return messages_words[0]
  }

  // Check lengths of each message's words
  if (messages_words.some(words => words.length != messages_words[0].length)) {
      throw new Error('Message lengths are not equal!')
  }

  // Compare each word in messages, replace different words with placeholders
  let fingerprint = []
  for (let i = 0; i < messages_words[0].length; i++) {
      let word = messages_words[0][i]
      let isSame = messages_words.every(words => words[i] == word)
      if (isSame) {
          fingerprint.push(word)
      } else {
          fingerprint.push('_nonce_')
      }
  }

  return fingerprint
}

/**
* Compare two fingerprints
*
* @param {Array} f1
*      input a fingerprint (array) or a message (string)
*
* @param {Array} f2
*      input a fingerprint (array) or a message (string)
*
* @returns {Boolean} isSame
*/
function compareFingerprint (f1, f2) {

  if (f1.length != f2.length) {
      return false
  }

  for (let i = 0; i < f1.length; i++) {
      let word1 = f1[i]
      let word2 = f2[i]

      // A message may not replace nonce with '_nonce_'.
      // So if '_nonce_' appears in f1 or f2, we should skip it.
      if (word1 == '_nonce_' || word2 == '_nonce_') {
          continue
      }

      if (word1 != word2) {
          return false
      }
  }

  return true
}

/**
 *
 * @param {Object} message
 *   {address,message,domain,web3Name}
 * @param {Object} globalFingerprints
 *  web3Storage.globalFingerprints
 * @returns {Object} messageInfo
 *  {address,message,createdAt,domain,web3Name,fingerprint}
 */
export function createMessageInfo(msg, globalFingerprints){
  let messageInfo = {
      address: msg.address,
      message: msg.message,
      createdAt: Date.now(),
      domain: msg.domain,
      web3Name: msg.web3Name,
      fingerprint: []
  }

  let messageList = [messageInfo.message]
  // Try to find the same fingerprint from globalFingerprints, according to domain
  if (globalFingerprints[messageInfo.domain]) {
      messageList.push(globalFingerprints[messageInfo.domain])
  }
  try {
      messageInfo.fingerprint = generateFingerprint(messageList)
  } catch (error) {
      // if website update the message, the fingerprint will be different, so we use the latest message to generate fingerprint again.
      messageInfo.fingerprint = generateFingerprint([messageInfo.message])
  }

  return messageInfo
}

/**
*Message:
* 1. Should include a domain name to prevent phishing attacks
* 2. Should include a nonce to prevent replay attacks
*
* Security Detection:
* 1. Phishing Attack:
*    Danger: If the message is signed by other domain, it may be a phishing attack.
*    Warning: If the message is likely to the message of other domain, it may be a phishing attack.
*    Info: If the message does not include domain name, it has the risk of phishing attack.
*
* 2. Replay Attack: Check if nonce in message
*    - If yes, this message have the risk of replay attack
* @param {Object} message
*    {address,message,createdAt,expiredAt,domain,web3Name}
*
* @param {Object} signedMessages
*    web3Storage.signedMessages
*
* @param {Object} globalFingerprints
*    web3Storage.globalFingerprints
*/
export function checkMessageBeforeSign(messageInfo, signedMessages, globalFingerprints){

  let {address, message, domain, fingerprint} = messageInfo

  /**
   * Danger:
   *  Phishing Attack: This website may be a phishing site. You had signed similar messages for [domains]. Please check this website's domain name.
   * Warning:
   *  Phishing Attack: This website has the risk of phishing attack. The message you signed does not include domain name. Please check this website's domain name.
   *  Replay Attack: This message has the risk of replay attack. Please check this website's domain name.
   */
  let Risks = []



    // Info: Phishing Attack
  let domainInMsg = message.toLowerCase().indexOf(domain.toLowerCase()) != -1
  if (!domainInMsg) {
      Risks.push({
        severity: 'info',
          title: 'Phishing Attack',
          body: 'This website has the risk of phishing attack. The message you signed does not include domain name. Please check this website\'s domain name.'
      })
  }


  // Warning: Phishing Attack
  // different domain, same fingerprint
  let similarDomains = []
  for (let d in globalFingerprints) {
      if (d == domain) continue // Skip the same domain
      let f2 = globalFingerprints[d]
      if (compareFingerprint(fingerprint, f2)) {
            similarDomains.push(d)
      }
  }
    if (similarDomains.length > 0) {
        if (Risks.length > 0){ Risks.pop() }

        Risks.push({
            severity: 'warning',
              title: 'Phishing Attack',
              body: `This message is the same as other websites. This website can use your signature to log in to other websites!\n ${similarDomains.join(', ')}`
          })
    }

  // Danger: Phishing Attack
  // Check address's localFingerprints, if fingerprint is same, and domain is different, this domain may be a phishing website.

    // If this message is the first message of the address, we don't need to check fingerprint.
    if (signedMessages[address] != undefined) {
        let {localFingerprints} = signedMessages[address]
        let f1 = fingerprint
        let victim_domains = []
        for (let d in localFingerprints) {
            if (d == domain) continue // Skip the same domain
            let f2 = localFingerprints[d]
            if (compareFingerprint(f1, f2)) { victim_domains.push(d) }
        }

        if (victim_domains.length > 0) {
            if (Risks.length > 0){ Risks.pop() }
            Risks.push({
            severity: 'danger',
                title: 'Phishing Attack',
                body: `This is a phishing website.\n This website's domain is ${domain}. You had signed similar messages on ${victim_domains.join(', ')}. Please check this website's domain name.`
            })
        }
    }

    // Info: Replay Attack
    //if no localFingerprints, this is the first sign this message, we refer to globalFingerprints
    let nonceInMsg = false

    if (signedMessages[address] != undefined && signedMessages[address].localFingerprints[domain] != undefined) {
        // Check whether nonce in message's fingerprint
        nonceInMsg = fingerprint.some(item => item == '_nonce_')
    }else{
        if (similarDomains.length >0){
            let similarFingerprint = globalFingerprints[similarDomains[0]]
            nonceInMsg = similarFingerprint.some(item => item == '_nonce_')
        }
    }


  if (!nonceInMsg) {
      Risks.push({
        severity: 'info',
          title: 'Replay Attack',
          body: 'This message has the risk of replay attack, because it does not include nonce.'
      })
  }

  return Risks
}
