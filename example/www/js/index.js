/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

var CDVCrypt;

var jqmReady = $.Deferred();
var pgReady = $.Deferred();

var app = {
    // Application Constructor
    initialize: function(callback) {
        this.callback = callback;
        this.bindEvents();
    },
    // Bind Event Listeners
    //
    // Bind any events that are required on startup. Common events are:
    // 'load', 'deviceready', 'offline', and 'online'.
    bindEvents: function() {
        document.addEventListener('deviceready', this.onDeviceReady, false);
    },
    // deviceready Event Handler
    //
    // The scope of 'this' is the event. In order to call the 'receivedEvent'
    // function, we must explicitly call 'app.receivedEvent(...);'
    onDeviceReady: function() {
        pgReady.resolve();
        app.receivedEvent('deviceready');
    },
    // Update DOM on a Received Event
    receivedEvent: function(id) {
        var parentElement = document.getElementById(id);
        var listeningElement = parentElement.querySelector('.listening');
        var receivedElement = parentElement.querySelector('.received');

        listeningElement.setAttribute('style', 'display:none;');
        receivedElement.setAttribute('style', 'display:block;');

        console.log('Received Event: ' + id);
    }
};

$(document).on("pagecreate", function()
{
  //Resolve jQuery Mobile
  jqmReady.resolve();
  $(document).off("pagecreate");
});

$.when(jqmReady, pgReady).then(function()
{
  //When PhoneGap and jQuery Mobile are resolved, start the app
  if (app.callback !== null)
  {
    app.callback();
  }
});

app.initialize(function() {
  console.log('initialize:');
  CDVCrypt.initialize(function(args){
      $('#output').html("Initialized");
      CDVCrypt.getPublicKey(function(args){
          console.log(args);
          $('#inPublic').val(args.publickey);
        },
        function(args){},
        {});
    },
    function(args){},
    {});
  $('#inToken').on('change', function(){
    CDVCrypt.setToken(function(args){
        $('#output').html("token updated");
      },
      function(args){},
      {
        token: $('#inToken').val()
      });
  })
  $('#encode').on('vclick', function(){
    CDVCrypt.encrypt(function(args){
        $('#output').html("Encoded: </br>"+args.message);
        $('#inEncoded').val(args.message);
      },
      function(args){},
      {
        message: $('#inMessage').val()
      });
  })
  $('#decode').on('vclick', function(){
    CDVCrypt.decrypt(function(args){
        $('#output').html("Decoded: </br>"+args.message);
      },
      function(args){},
      {
        message: $('#inEncoded').val()
      });
  })
  $('#encodersa').on('vclick', function(){
    CDVCrypt.encryptPublic(function(args){
        $('#output').html("Encoded: </br>"+args.message);
        $('#inEncoded').val(args.message);
      },
      function(args){},
      {
        message: $('#inMessage').val()
      });
  })
  $('#decodersa').on('vclick', function(){
    CDVCrypt.decryptPrivate(function(args){
        $('#output').html("Decoded: </br>"+args.message);
      },
      function(args){},
      {
        message: $('#inEncoded').val()
      });
  })
});
