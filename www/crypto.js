var cryptoName = "CordovaCrypt";
var AESCrypt = {
  initialize: function(successCallback, errorCallback, params) {
    cordova.exec(successCallback, errorCallback, cryptoName, "initialize", [params]);
  },
  encrypt: function(successCallback, errorCallback, params) {
    cordova.exec(successCallback, errorCallback, cryptoName, "encrypt", [params]);
  },
  decrypt: function(successCallback, errorCallback, params) {
    cordova.exec(successCallback, errorCallback, cryptoName, "decrypt", [params]);
  }
}
module.exports = AESCrypt;
