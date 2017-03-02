//
//  TouchIdManager.swift
//  TouchIdAPI
//
//  Created by Manish Kumar on 3/1/17.
//  Copyright © 2017 Manish Kumar. All rights reserved.
//

import UIKit
import LocalAuthentication
import Security

// Constant Identifiers
let userAccount = "AuthenticatedUser"
let accessGroup = "SecuritySerivice"

/**
 *  User defined keys for new entry
 *  Note: add new keys for new secure item and use them in load and save methods
 */

let passwordKey = "Refresh-Token"
let authenticatValue = "Authenticate To Get Your Name"

let kSecClassValue = NSString(format: kSecClass)
let kSecAttrAccountValue = NSString(format: kSecAttrAccount)
let kSecValueDataValue = NSString(format: kSecValueData)
let kSecClassGenericPasswordValue = NSString(format: kSecClassGenericPassword)
let kSecAttrServiceValue = NSString(format: kSecAttrService)
let kSecMatchLimitValue = NSString(format: kSecMatchLimit)
let kSecReturnDataValue = NSString(format: kSecReturnData)
let kSecMatchLimitOneValue = NSString(format: kSecMatchLimitOne)
let kSecAttrAccessControlValue = NSString(format: kSecAttrAccessControl)
let kSecUseOperationPromptValue = NSString(format: kSecUseOperationPrompt)

class TouchIdManager: NSObject {
    public class func savePassword(token: NSString) {
        self.save(service: passwordKey as NSString, data: token)
    }
    public class func loadPassword() -> NSString? {
        return self.load(service: passwordKey as NSString)
    }
    private class func save(service: NSString, data: NSString) {
        var error : Unmanaged<CFError>? = nil
        //Create ACL For An Item
        let secACL = SecAccessControlCreateWithFlags(kCFAllocatorSystemDefault,
                                                     kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                     .userPresence,
                                                     &error)
        
        let dataFromString = data.data(using: String.Encoding.utf8.rawValue,
                                       allowLossyConversion: false)! as NSData
        
        // Instantiate a new default keychain query
        let keychainQuery = NSMutableDictionary(objects: [kSecClassGenericPasswordValue,
                                                                               service,
                                                                               userAccount,
                                                                               dataFromString,
                                                                               secACL!],
                                                                     forKeys: [kSecClassValue,
                                                                               kSecAttrServiceValue, kSecAttrAccountValue, kSecValueDataValue,
                                                                               kSecAttrAccessControlValue])
        // Delete any existing items
        SecItemDelete(keychainQuery as CFDictionary)
        // Add the new keychain item
        SecItemAdd(keychainQuery as CFDictionary, nil)
    }
    private class func load(service: NSString) -> NSString? {
        let keychainQuery: NSMutableDictionary = NSMutableDictionary(objects: [kSecClassGenericPasswordValue,
                                                                               service,
                                                                               userAccount,
                                                                               kCFBooleanTrue,
                                                                               kSecMatchLimitOneValue,
                                                                               authenticatValue],
                                                                     forKeys: [kSecClassValue,
                                                                               kSecAttrServiceValue, kSecAttrAccountValue, kSecReturnDataValue, kSecMatchLimitValue,
                                                                               kSecUseOperationPromptValue])
        
        var dataTypeRef :AnyObject?
        // Search for the keychain items
        let status: OSStatus = SecItemCopyMatching(keychainQuery, &dataTypeRef)
        var contentsOfKeychain: NSString? = nil
        
        if status == errSecSuccess {
            if let retrievedData = dataTypeRef as? NSData {
                contentsOfKeychain = NSString(data: retrievedData as Data, encoding: String.Encoding.utf8.rawValue)
            }
        } else {
            print("Nothing was retrieved from the keychain. Status code \(status)")
        }
        
        return contentsOfKeychain
    }
    
}
