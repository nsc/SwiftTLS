//
//  Identity.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 02.07.16.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

import Foundation

public protocol Identity
{
    var certificateChain: [X509.Certificate] { get }
    func signer(with hashAlgorithm: HashAlgorithm) -> Signing
}
