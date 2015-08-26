var cryptoName = "CordovaCrypt";
var AESCrypt = {
  initialize: function(successCallback, errorCallback, params) {
    cordova.exec(successCallback, errorCallback, cryptoName, "initialize", [params]);
  },
  encrypt: function(successCallback, errorCallback, params) {
    cordova.exec(successCallback, errorCallback, cryptoName, "encrypt", [params]);
  },
  decyrpt: function(successCallback, errorCallback, params) {
    cordova.exec(successCallback, errorCallback, cryptoName, "decyrpt", [params]);
  }
}
module.exports = AESCrypt;
