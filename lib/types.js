
/**
 * @global
 * @typedef {function(Error?, any?):void} cbType
 *
 */

/**
 * @global
 * @typedef {Object} ruleEngineType
 */

/**
 * @global
 * @typedef {Object} CANameType
 * @property {string=} caOwner
 * @property {string=} caLocalName
 */


/**
 * @global
 * @typedef {Object} simpleRuleType
 * @property {string} type Should be 'caf.simpleRule'.
 * @property {CANameType=} ac Enabled CAs.
 * @property {(Array.<string> | string)=} methods The methods enabled. All
 * enabled if this field is missing.
 */

/**
 * @global
 * @typedef {Object} aggregateRuleType
 * @property {string} type Should be 'caf.aggregateRule'.
 * @property {string} alias A local alias for the aggregate map.
 * @property {(Array.<string> | string)=} methods The methods enabled. All
 * enabled if this field is missing.
 */


/**
 * @global
 * @typedef {simpleRuleType | aggregateRuleType} ruleType
 */

/**
 * @global
 * @typedef {Object} tokenDescriptionType
 * @property {(string|null)=} appPublisher The publisher of the app hosting CAs.
 * A `null` value means  force the current value.
 * @property {(string|null)=} appLocalName The name of the app in the
 *  `appPublisher`  context.
 * @property {(string|null)=} caOwner  The owner of the CA.
 * @property {(string|null)=} caLocalName The name of the CA in the owner's
 * context.
 * @property {number=} durationInSec Time in sec before token expiration.
 */

/**
 * @global
 * @typedef {Array.<tokenDescriptionType> | tokenDescriptionType} tkDescArray
 */

/**
 * @global
 * @typedef {Object} tokenType
 * @property {string=} appPublisher The publisher of the app hosting CAs.
 * @property {string=} appLocalName The name of the app in the `appPublisher`
 *  context.
 * @property {string=} caOwner The owner of the CA.
 * @property {string=} caLocalName The name of the CA in the owner's context.
 * @property {number=} expiresAfter UTC expire time in msec since 1970.
 */

/**
 * @global
 * @typedef {Object} specType
 * @property {string} name
 * @property {string|null} module
 * @property {string=} description
 * @property {Object} env
 * @property {Array.<specType>=} components
 *
 */

/**
 * @global
 * @typedef {Object} specDeltaType
 * @property {string=} name
 * @property {(string|null)=} module
 * @property {string=} description
 * @property {Object=} env
 * @property {Array.<specType>=} components
 *
 */

/**
 * @global
 * @typedef {Object.<string, Object>} ctxType
 */
