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

let kSecClassValue = NSString(format: kSecClass)
let kSecAttrAccountValue = NSString(format: kSecAttrAccount)
let kSecValueDataValue = NSString(format: kSecValueData)
let kSecClassGenericPasswordValue = NSString(format: kSecClassGenericPassword)
let kSecAttrServiceValue = NSString(format: kSecAttrService)
let kSecMatchLimitValue = NSString(format: kSecMatchLimit)
let kSecReturnDataValue = NSString(format: kSecReturnData)
let kSecMatchLimitOneValue = NSString(format: kSecMatchLimitOne)
let kSecAttrAccessControlValue = NSString(format: kSecAttrAccessControl)

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
                                                                               service, userAccount,
                                                                               kCFBooleanTrue,
                                                                               kSecMatchLimitOneValue],
                                                                     forKeys: [kSecClassValue,
                                                                               kSecAttrServiceValue, kSecAttrAccountValue, kSecReturnDataValue, kSecMatchLimitValue])
        
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
    
    /*
    func addRefereshToken(with token : String) -> OSStatus {
        var error: Unmanaged<CFError>?;
        let sacRef = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                     kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                     .userPresence,
                                                     &error)
        
        print(sacRef.debugDescription)
        
        
        let data = "manish".data(using: String.Encoding.utf8, allowLossyConversion: false)! as Data;
        let attributes = NSMutableDictionary(
            objects: [  kSecClassGenericPassword,
                        "logon service",
                        data,
                        kCFBooleanTrue,
                        sacRef!
            ],
            forKeys: [  kSecClass as! NSCopying,
                        kSecAttrService as! NSCopying,
                        kSecValueData as! NSCopying,
                        kSecUseAuthenticationUIAllow as! NSCopying,
                        kSecAttrAccessControl as! NSCopying]);
        
        let status: OSStatus = SecItemAdd(attributes, nil)
        return status
    }
    func fetchKeychainItem(with token : String) {
        DispatchQueue.global().async {
            let select_query: NSDictionary = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: "logon service",
                kSecAttrAccount: "User Account",
                kSecReturnData: true,
                kSecUseOperationPrompt: "Authenticate to access secret message"
            ]
            var extractedData: CFTypeRef?
            let select_status = SecItemCopyMatching(select_query, &extractedData)
            if select_status == errSecSuccess {
                if let retrievedData = extractedData as? Data,
                    let secretMessage = String(data: retrievedData, encoding: .utf8) {
                    print("Secret message: \(secretMessage)")
                } else {
                    print("Invalid data")
                }
            } else if select_status == errSecUserCanceled {
                print("User canceled the operation.")
            } else {
                print("SELECT Error: \(select_status).")
            }
        }
    }*/
}
