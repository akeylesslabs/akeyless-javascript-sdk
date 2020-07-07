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

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD.
    define(['expect.js', process.cwd()+'/src/com.akeyless.api_gateway.swagger/index'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    factory(require('expect.js'), require(process.cwd()+'/src/com.akeyless.api_gateway.swagger/index'));
  } else {
    // Browser globals (root is window)
    factory(root.expect, root.AkeylessVaultApi);
  }
}(this, function(expect, AkeylessVaultApi) {
  'use strict';

  var instance;

  beforeEach(function() {
    instance = new AkeylessVaultApi.DefaultApi();
  });

  var getProperty = function(object, getter, property) {
    // Use getter method if present; otherwise, get the property directly.
    if (typeof object[getter] === 'function')
      return object[getter]();
    else
      return object[property];
  }

  var setProperty = function(object, setter, property, value) {
    // Use setter method if present; otherwise, set the property directly.
    if (typeof object[setter] === 'function')
      object[setter](value);
    else
      object[property] = value;
  }

  describe('DefaultApi', function() {
    describe('assocRoleAm', function() {
      it('should call assocRoleAm successfully', function(done) {
        //uncomment below and update the code to test assocRoleAm
        //instance.assocRoleAm(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('auth', function() {
      it('should call auth successfully', function(done) {
        //uncomment below and update the code to test auth
        //instance.auth(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('configure', function() {
      it('should call configure successfully', function(done) {
        //uncomment below and update the code to test configure
        //instance.configure(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('createAuthMethod', function() {
      it('should call createAuthMethod successfully', function(done) {
        //uncomment below and update the code to test createAuthMethod
        //instance.createAuthMethod(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('createAuthMethodAwsIam', function() {
      it('should call createAuthMethodAwsIam successfully', function(done) {
        //uncomment below and update the code to test createAuthMethodAwsIam
        //instance.createAuthMethodAwsIam(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('createAuthMethodAzureAd', function() {
      it('should call createAuthMethodAzureAd successfully', function(done) {
        //uncomment below and update the code to test createAuthMethodAzureAd
        //instance.createAuthMethodAzureAd(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('createAuthMethodLdap', function() {
      it('should call createAuthMethodLdap successfully', function(done) {
        //uncomment below and update the code to test createAuthMethodLdap
        //instance.createAuthMethodLdap(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('createAuthMethodOauth2', function() {
      it('should call createAuthMethodOauth2 successfully', function(done) {
        //uncomment below and update the code to test createAuthMethodOauth2
        //instance.createAuthMethodOauth2(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('createAuthMethodSaml', function() {
      it('should call createAuthMethodSaml successfully', function(done) {
        //uncomment below and update the code to test createAuthMethodSaml
        //instance.createAuthMethodSaml(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('createDynamicSecret', function() {
      it('should call createDynamicSecret successfully', function(done) {
        //uncomment below and update the code to test createDynamicSecret
        //instance.createDynamicSecret(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('createKey', function() {
      it('should call createKey successfully', function(done) {
        //uncomment below and update the code to test createKey
        //instance.createKey(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('createPkiCertIssuer', function() {
      it('should call createPkiCertIssuer successfully', function(done) {
        //uncomment below and update the code to test createPkiCertIssuer
        //instance.createPkiCertIssuer(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('createRole', function() {
      it('should call createRole successfully', function(done) {
        //uncomment below and update the code to test createRole
        //instance.createRole(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('createSecret', function() {
      it('should call createSecret successfully', function(done) {
        //uncomment below and update the code to test createSecret
        //instance.createSecret(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('createSshCertIssuer', function() {
      it('should call createSshCertIssuer successfully', function(done) {
        //uncomment below and update the code to test createSshCertIssuer
        //instance.createSshCertIssuer(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('decrypt', function() {
      it('should call decrypt successfully', function(done) {
        //uncomment below and update the code to test decrypt
        //instance.decrypt(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('decryptFile', function() {
      it('should call decryptFile successfully', function(done) {
        //uncomment below and update the code to test decryptFile
        //instance.decryptFile(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('decryptPkcs1', function() {
      it('should call decryptPkcs1 successfully', function(done) {
        //uncomment below and update the code to test decryptPkcs1
        //instance.decryptPkcs1(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('deleteAssoc', function() {
      it('should call deleteAssoc successfully', function(done) {
        //uncomment below and update the code to test deleteAssoc
        //instance.deleteAssoc(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('deleteAuthMethod', function() {
      it('should call deleteAuthMethod successfully', function(done) {
        //uncomment below and update the code to test deleteAuthMethod
        //instance.deleteAuthMethod(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('deleteItem', function() {
      it('should call deleteItem successfully', function(done) {
        //uncomment below and update the code to test deleteItem
        //instance.deleteItem(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('deleteRole', function() {
      it('should call deleteRole successfully', function(done) {
        //uncomment below and update the code to test deleteRole
        //instance.deleteRole(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('deleteRoleRule', function() {
      it('should call deleteRoleRule successfully', function(done) {
        //uncomment below and update the code to test deleteRoleRule
        //instance.deleteRoleRule(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('describeItem', function() {
      it('should call describeItem successfully', function(done) {
        //uncomment below and update the code to test describeItem
        //instance.describeItem(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('encrypt', function() {
      it('should call encrypt successfully', function(done) {
        //uncomment below and update the code to test encrypt
        //instance.encrypt(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('encryptFile', function() {
      it('should call encryptFile successfully', function(done) {
        //uncomment below and update the code to test encryptFile
        //instance.encryptFile(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('encryptPkcs1', function() {
      it('should call encryptPkcs1 successfully', function(done) {
        //uncomment below and update the code to test encryptPkcs1
        //instance.encryptPkcs1(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('getAuthMethod', function() {
      it('should call getAuthMethod successfully', function(done) {
        //uncomment below and update the code to test getAuthMethod
        //instance.getAuthMethod(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('getCloudIdentity', function() {
      it('should call getCloudIdentity successfully', function(done) {
        //uncomment below and update the code to test getCloudIdentity
        //instance.getCloudIdentity(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('getDynamicSecretValue', function() {
      it('should call getDynamicSecretValue successfully', function(done) {
        //uncomment below and update the code to test getDynamicSecretValue
        //instance.getDynamicSecretValue(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('getPkiCertificate', function() {
      it('should call getPkiCertificate successfully', function(done) {
        //uncomment below and update the code to test getPkiCertificate
        //instance.getPkiCertificate(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('getRole', function() {
      it('should call getRole successfully', function(done) {
        //uncomment below and update the code to test getRole
        //instance.getRole(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('getRsaPublic', function() {
      it('should call getRsaPublic successfully', function(done) {
        //uncomment below and update the code to test getRsaPublic
        //instance.getRsaPublic(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('getSecretValue', function() {
      it('should call getSecretValue successfully', function(done) {
        //uncomment below and update the code to test getSecretValue
        //instance.getSecretValue(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('getSshCertificate', function() {
      it('should call getSshCertificate successfully', function(done) {
        //uncomment below and update the code to test getSshCertificate
        //instance.getSshCertificate(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('help', function() {
      it('should call help successfully', function(done) {
        //uncomment below and update the code to test help
        //instance.help(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('listAuthMethods', function() {
      it('should call listAuthMethods successfully', function(done) {
        //uncomment below and update the code to test listAuthMethods
        //instance.listAuthMethods(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('listItems', function() {
      it('should call listItems successfully', function(done) {
        //uncomment below and update the code to test listItems
        //instance.listItems(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('listRoles', function() {
      it('should call listRoles successfully', function(done) {
        //uncomment below and update the code to test listRoles
        //instance.listRoles(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('setRoleRule', function() {
      it('should call setRoleRule successfully', function(done) {
        //uncomment below and update the code to test setRoleRule
        //instance.setRoleRule(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('signPkcs1', function() {
      it('should call signPkcs1 successfully', function(done) {
        //uncomment below and update the code to test signPkcs1
        //instance.signPkcs1(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('unconfigure', function() {
      it('should call unconfigure successfully', function(done) {
        //uncomment below and update the code to test unconfigure
        //instance.unconfigure(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('update', function() {
      it('should call update successfully', function(done) {
        //uncomment below and update the code to test update
        //instance.update(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('updateItem', function() {
      it('should call updateItem successfully', function(done) {
        //uncomment below and update the code to test updateItem
        //instance.updateItem(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('updateRole', function() {
      it('should call updateRole successfully', function(done) {
        //uncomment below and update the code to test updateRole
        //instance.updateRole(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('updateSecretVal', function() {
      it('should call updateSecretVal successfully', function(done) {
        //uncomment below and update the code to test updateSecretVal
        //instance.updateSecretVal(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('uploadPkcs12', function() {
      it('should call uploadPkcs12 successfully', function(done) {
        //uncomment below and update the code to test uploadPkcs12
        //instance.uploadPkcs12(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('uploadRsa', function() {
      it('should call uploadRsa successfully', function(done) {
        //uncomment below and update the code to test uploadRsa
        //instance.uploadRsa(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('verifyPkcs1', function() {
      it('should call verifyPkcs1 successfully', function(done) {
        //uncomment below and update the code to test verifyPkcs1
        //instance.verifyPkcs1(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
  });

}));