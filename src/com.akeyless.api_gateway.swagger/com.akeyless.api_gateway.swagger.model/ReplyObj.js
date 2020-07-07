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
 * The ReplyObj model module.
 * @module com.akeyless.api_gateway.swagger/com.akeyless.api_gateway.swagger.model/ReplyObj
 * @version 0.1.1
 */
class ReplyObj {
    /**
     * Constructs a new <code>ReplyObj</code>.
     * Base response
     * @alias module:com.akeyless.api_gateway.swagger/com.akeyless.api_gateway.swagger.model/ReplyObj
     */
    constructor() { 
        
        ReplyObj.initialize(this);
    }

    /**
     * Initializes the fields of this object.
     * This method is used by the constructors of any subclasses, in order to implement multiple inheritance (mix-ins).
     * Only for internal use.
     */
    static initialize(obj) { 
    }

    /**
     * Constructs a <code>ReplyObj</code> from a plain JavaScript object, optionally creating a new instance.
     * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
     * @param {Object} data The plain JavaScript object bearing properties of interest.
     * @param {module:com.akeyless.api_gateway.swagger/com.akeyless.api_gateway.swagger.model/ReplyObj} obj Optional instance to populate.
     * @return {module:com.akeyless.api_gateway.swagger/com.akeyless.api_gateway.swagger.model/ReplyObj} The populated <code>ReplyObj</code> instance.
     */
    static constructFromObject(data, obj) {
        if (data) {
            obj = obj || new ReplyObj();

            if (data.hasOwnProperty('command')) {
                obj['command'] = ApiClient.convertToType(data['command'], 'String');
            }
            if (data.hasOwnProperty('response')) {
                obj['response'] = ApiClient.convertToType(data['response'], Object);
            }
            if (data.hasOwnProperty('status')) {
                obj['status'] = ApiClient.convertToType(data['status'], 'String');
            }
            if (data.hasOwnProperty('token')) {
                obj['token'] = ApiClient.convertToType(data['token'], 'String');
            }
        }
        return obj;
    }


}

/**
 * @member {String} command
 */
ReplyObj.prototype['command'] = undefined;

/**
 * @member {Object} response
 */
ReplyObj.prototype['response'] = undefined;

/**
 * @member {String} status
 */
ReplyObj.prototype['status'] = undefined;

/**
 * @member {String} token
 */
ReplyObj.prototype['token'] = undefined;






export default ReplyObj;
