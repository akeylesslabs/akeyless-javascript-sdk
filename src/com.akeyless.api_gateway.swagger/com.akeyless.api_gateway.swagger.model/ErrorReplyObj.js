/**
 * AKEYLESS Vault API
 * RESTFull API for interacting with AKEYLESS Vault API
 *
 * The version of the OpenAPI document: 0.1.1
 * Contact: refael@akeyless.io
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 *
 */

import ApiClient from '../ApiClient';

/**
 * The ErrorReplyObj model module.
 * @module com.akeyless.api_gateway.swagger/com.akeyless.api_gateway.swagger.model/ErrorReplyObj
 * @version 0.1.1
 */
class ErrorReplyObj {
    /**
     * Constructs a new <code>ErrorReplyObj</code>.
     * Response with error description
     * @alias module:com.akeyless.api_gateway.swagger/com.akeyless.api_gateway.swagger.model/ErrorReplyObj
     */
    constructor() { 
        
        ErrorReplyObj.initialize(this);
    }

    /**
     * Initializes the fields of this object.
     * This method is used by the constructors of any subclasses, in order to implement multiple inheritance (mix-ins).
     * Only for internal use.
     */
    static initialize(obj) { 
    }

    /**
     * Constructs a <code>ErrorReplyObj</code> from a plain JavaScript object, optionally creating a new instance.
     * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
     * @param {Object} data The plain JavaScript object bearing properties of interest.
     * @param {module:com.akeyless.api_gateway.swagger/com.akeyless.api_gateway.swagger.model/ErrorReplyObj} obj Optional instance to populate.
     * @return {module:com.akeyless.api_gateway.swagger/com.akeyless.api_gateway.swagger.model/ErrorReplyObj} The populated <code>ErrorReplyObj</code> instance.
     */
    static constructFromObject(data, obj) {
        if (data) {
            obj = obj || new ErrorReplyObj();

            if (data.hasOwnProperty('error')) {
                obj['error'] = ApiClient.convertToType(data['error'], 'String');
            }
            if (data.hasOwnProperty('message')) {
                obj['message'] = ApiClient.convertToType(data['message'], 'String');
            }
        }
        return obj;
    }


}

/**
 * Internal error code
 * @member {String} error
 */
ErrorReplyObj.prototype['error'] = undefined;

/**
 * Error message
 * @member {String} message
 */
ErrorReplyObj.prototype['message'] = undefined;






export default ErrorReplyObj;
