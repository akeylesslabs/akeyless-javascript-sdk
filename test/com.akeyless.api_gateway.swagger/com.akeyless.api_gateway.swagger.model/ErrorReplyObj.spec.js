/*
 * AKEYLESS Vault API
 * RESTFull API for interacting with AKEYLESS Vault API
 *
 * OpenAPI spec version: 0.1.1
 * Contact: refael@akeyless.io
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 *
 * Swagger Codegen version: 2.4.14
 *
 * Do not edit the class manually.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD.
    define(['expect.js', '../../../src/com.akeyless.api_gateway.swagger/index'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    factory(require('expect.js'), require('../../../src/com.akeyless.api_gateway.swagger/index'));
  } else {
    // Browser globals (root is window)
    factory(root.expect, root.AkeylessVaultApi);
  }
}(this, function(expect, AkeylessVaultApi) {
  'use strict';

  var instance;

  describe('com.akeyless.api_gateway.swagger', function() {
    describe('ErrorReplyObj', function() {
      beforeEach(function() {
        instance = new AkeylessVaultApi.ErrorReplyObj();
      });

      it('should create an instance of ErrorReplyObj', function() {
        // TODO: update the code to test ErrorReplyObj
        expect(instance).to.be.a(AkeylessVaultApi.ErrorReplyObj);
      });

      it('should have the property error (base name: "error")', function() {
        // TODO: update the code to test the property error
        expect(instance).to.have.property('error');
        // expect(instance.error).to.be(expectedValueLiteral);
      });

      it('should have the property message (base name: "message")', function() {
        // TODO: update the code to test the property message
        expect(instance).to.have.property('message');
        // expect(instance.message).to.be(expectedValueLiteral);
      });

    });
  });

}));
