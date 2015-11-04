var cryptoName = "CordovaCrypt";
var CDVCrypt = {
  initialize: function(successCallback, errorCallback, params) {
    cordova.exec(successCallback, errorCallback, cryptoName, "initialize", [params]);
  },
  setToken: function(successCallback, errorCallback, params) {
    cordova.exec(successCallback, errorCallback, cryptoName, "setToken", [params]);
  },
  encrypt: function(successCallback, errorCallback, params) {
    cordova.exec(successCallback, errorCallback, cryptoName, "encrypt", [params]);
  },
  decrypt: function(successCallback, errorCallback, params) {
    cordova.exec(successCallback, errorCallback, cryptoName, "decrypt", [params]);
  },
  encryptPublic: function(successCallback, errorCallback, params) {
    cordova.exec(successCallback, errorCallback, cryptoName, "encryptPublic", [params]);
  },
  decryptPrivate: function(successCallback, errorCallback, params) {
    cordova.exec(successCallback, errorCallback, cryptoName, "decryptPrivate", [params]);
  },
  getPublicKey: function(successCallback, errorCallback, params) {
    cordova.exec(successCallback, errorCallback, cryptoName, "getPublicKey", [params]);
  }
}
module.exports = CDVCrypt;
