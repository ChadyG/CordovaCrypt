var cryptoName = "CordovaCrypt";
var crypto = {
  initialize: function(successCallback, errorCallback, params) {
    cordova.exec(successCallback, errorCallback, bluetoothleName, "initialize", [params]);
  }
}
module.exports = crypto;
