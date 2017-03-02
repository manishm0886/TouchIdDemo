//
//  ViewController.swift
//  TouchIdAPI
//
//  Created by Manish Kumar on 3/1/17.
//  Copyright © 2017 Manish Kumar. All rights reserved.
//

import UIKit

class ViewController: UIViewController {
    let touchIdManager = TouchIdManager.init()
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        print(TouchIdManager.loadPassword() ?? "Gaand Mar Gai")
        TouchIdManager.savePassword(token: "Manish Kumar")
    }
    @IBAction func launchTouchId(_ sender: Any) {
        print(TouchIdManager.loadPassword() ?? "Gaand Mar Gai")
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }


}

