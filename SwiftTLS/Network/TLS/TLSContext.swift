//
//  TLSContext.swift
//  Chat
//
//  Created by Nico Schmidt on 21.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation
    
public enum CipherSuite : UInt16 {
    
    case TLS_NULL_WITH_NULL_NULL = 0x00
    case TLS_RSA_WITH_NULL_MD5 = 0x01
    case TLS_RSA_WITH_NULL_SHA = 0x02
    case TLS_RSA_WITH_RC4_128_MD5 = 0x04
    case TLS_RSA_WITH_RC4_128_SHA = 0x05
    case TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x0A
    case TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = 0x0D
    case TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x10
    case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x13
    case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x16
    case TLS_DH_anon_WITH_RC4_128_MD5 = 0x18
    case TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = 0x1B
    case TLS_RSA_WITH_AES_128_CBC_SHA = 0x2F
    case TLS_DH_DSS_WITH_AES_128_CBC_SHA = 0x30
    case TLS_DH_RSA_WITH_AES_128_CBC_SHA = 0x31
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x32
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x33
    case TLS_DH_anon_WITH_AES_128_CBC_SHA = 0x34
    case TLS_RSA_WITH_AES_256_CBC_SHA = 0x35
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA = 0x36
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA = 0x37
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x38
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x39
    case TLS_DH_anon_WITH_AES_256_CBC_SHA = 0x3A
    case TLS_RSA_WITH_NULL_SHA256 = 0x3B
    case TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x3C
    case TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x3D
    case TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = 0x3E
    case TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = 0x3F
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = 0x40
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x67
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = 0x68
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = 0x69
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = 0x6A
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x6B
    case TLS_DH_anon_WITH_AES_128_CBC_SHA256 = 0x6C
    case TLS_DH_anon_WITH_AES_256_CBC_SHA256 = 0x6D

    case TLS_RSA_EXPORT_WITH_RC4_40_MD5 = 0x3
    case TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = 0x6
    case TLS_RSA_WITH_IDEA_CBC_SHA = 0x7
    case TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x8
    case TLS_RSA_WITH_DES_CBC_SHA = 0x9
    case TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = 0xb
    case TLS_DH_DSS_WITH_DES_CBC_SHA = 0xc
    case TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = 0xe
    case TLS_DH_RSA_WITH_DES_CBC_SHA = 0xf
    case TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x11
    case TLS_DHE_DSS_WITH_DES_CBC_SHA = 0x12
    case TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x14
    case TLS_DHE_RSA_WITH_DES_CBC_SHA = 0x15
    case TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 = 0x17
    case TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = 0x19
    case TLS_DH_anon_WITH_DES_CBC_SHA = 0x1a
    case TLS_KRB5_WITH_DES_CBC_SHA = 0x1e
    case TLS_KRB5_WITH_3DES_EDE_CBC_SHA = 0x1f
    case TLS_KRB5_WITH_RC4_128_SHA = 0x20
    case TLS_KRB5_WITH_IDEA_CBC_SHA = 0x21
    case TLS_KRB5_WITH_DES_CBC_MD5 = 0x22
    case TLS_KRB5_WITH_3DES_EDE_CBC_MD5 = 0x23
    case TLS_KRB5_WITH_RC4_128_MD5 = 0x24
    case TLS_KRB5_WITH_IDEA_CBC_MD5 = 0x25
    case TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = 0x26
    case TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = 0x27
    case TLS_KRB5_EXPORT_WITH_RC4_40_SHA = 0x28
    case TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = 0x29
    case TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = 0x2a
    case TLS_KRB5_EXPORT_WITH_RC4_40_MD5 = 0x2b
    case TLS_PSK_WITH_NULL_SHA = 0x2c
    case TLS_DHE_PSK_WITH_NULL_SHA = 0x2d
    case TLS_RSA_PSK_WITH_NULL_SHA = 0x2e
    case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x41
    case TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x42
    case TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x43
    case TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x44
    case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x45
    case TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA = 0x46
    case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x84
    case TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x85
    case TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x86
    case TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x87
    case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x88
    case TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA = 0x89
    case TLS_PSK_WITH_RC4_128_SHA = 0x8a
    case TLS_PSK_WITH_3DES_EDE_CBC_SHA = 0x8b
    case TLS_PSK_WITH_AES_128_CBC_SHA = 0x8c
    case TLS_PSK_WITH_AES_256_CBC_SHA = 0x8d
    case TLS_DHE_PSK_WITH_RC4_128_SHA = 0x8e
    case TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA = 0x8f
    case TLS_DHE_PSK_WITH_AES_128_CBC_SHA = 0x90
    case TLS_DHE_PSK_WITH_AES_256_CBC_SHA = 0x91
    case TLS_RSA_PSK_WITH_RC4_128_SHA = 0x92
    case TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA = 0x93
    case TLS_RSA_PSK_WITH_AES_128_CBC_SHA = 0x94
    case TLS_RSA_PSK_WITH_AES_256_CBC_SHA = 0x95
    case TLS_RSA_WITH_SEED_CBC_SHA = 0x96
    case TLS_DH_DSS_WITH_SEED_CBC_SHA = 0x97
    case TLS_DH_RSA_WITH_SEED_CBC_SHA = 0x98
    case TLS_DHE_DSS_WITH_SEED_CBC_SHA = 0x99
    case TLS_DHE_RSA_WITH_SEED_CBC_SHA = 0x9a
    case TLS_DH_anon_WITH_SEED_CBC_SHA = 0x9b
    case TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x9c
    case TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x9d
    case TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x9e
    case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x9f
    case TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = 0xa0
    case TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = 0xa1
    case TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = 0xa2
    case TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = 0xa3
    case TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = 0xa4
    case TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = 0xa5
    case TLS_DH_anon_WITH_AES_128_GCM_SHA256 = 0xa6
    case TLS_DH_anon_WITH_AES_256_GCM_SHA384 = 0xa7
    case TLS_PSK_WITH_AES_128_GCM_SHA256 = 0xa8
    case TLS_PSK_WITH_AES_256_GCM_SHA384 = 0xa9
    case TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = 0xaa
    case TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = 0xab
    case TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = 0xac
    case TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = 0xad
    case TLS_PSK_WITH_AES_128_CBC_SHA256 = 0xae
    case TLS_PSK_WITH_AES_256_CBC_SHA384 = 0xaf
    case TLS_PSK_WITH_NULL_SHA256 = 0xb0
    case TLS_PSK_WITH_NULL_SHA384 = 0xb1
    case TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = 0xb2
    case TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = 0xb3
    case TLS_DHE_PSK_WITH_NULL_SHA256 = 0xb4
    case TLS_DHE_PSK_WITH_NULL_SHA384 = 0xb5
    case TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = 0xb6
    case TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = 0xb7
    case TLS_RSA_PSK_WITH_NULL_SHA256 = 0xb8
    case TLS_RSA_PSK_WITH_NULL_SHA384 = 0xb9
    case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xba
    case TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 = 0xbb
    case TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xbc
    case TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 = 0xbd
    case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xbe
    case TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 = 0xbf
    case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0xc0
    case TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 = 0xc1
    case TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0xc2
    case TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 = 0xc3
    case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0xc4
    case TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 = 0xc5
    
    case TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0xff
    case TLS_FALLBACK_SCSV = 0x5600

    case TLS_ECDH_ECDSA_WITH_NULL_SHA = 0xc001
    case TLS_ECDH_ECDSA_WITH_RC4_128_SHA = 0xc002
    case TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xc003
    case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0xc004
    case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0xc005
    case TLS_ECDHE_ECDSA_WITH_NULL_SHA = 0xc006
    case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = 0xc007
    case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xc008
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xc009
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a
    case TLS_ECDH_RSA_WITH_NULL_SHA = 0xc00b
    case TLS_ECDH_RSA_WITH_RC4_128_SHA = 0xc00c
    case TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = 0xc00d
    case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = 0xc00e
    case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 0xc00f
    case TLS_ECDHE_RSA_WITH_NULL_SHA = 0xc010
    case TLS_ECDHE_RSA_WITH_RC4_128_SHA = 0xc011
    case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xc012
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014
    case TLS_ECDH_anon_WITH_NULL_SHA = 0xc015
    case TLS_ECDH_anon_WITH_RC4_128_SHA = 0xc016
    case TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA = 0xc017
    case TLS_ECDH_anon_WITH_AES_128_CBC_SHA = 0xc018
    case TLS_ECDH_anon_WITH_AES_256_CBC_SHA = 0xc019
    case TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA = 0xc01a
    case TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = 0xc01b
    case TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = 0xc01c
    case TLS_SRP_SHA_WITH_AES_128_CBC_SHA = 0xc01d
    case TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = 0xc01e
    case TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = 0xc01f
    case TLS_SRP_SHA_WITH_AES_256_CBC_SHA = 0xc020
    case TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0xc021
    case TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = 0xc022
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc023
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc024
    case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc025
    case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc026
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xc027
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xc028
    case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = 0xc029
    case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = 0xc02a
    case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b
    case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c
    case TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02d
    case TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02e
    case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f
    case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030
    case TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 0xc031
    case TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 0xc032
    case TLS_ECDHE_PSK_WITH_RC4_128_SHA = 0xc033
    case TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA = 0xc034
    case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = 0xc035
    case TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = 0xc036
    case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = 0xc037
    case TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = 0xc038
    case TLS_ECDHE_PSK_WITH_NULL_SHA = 0xc039
    case TLS_ECDHE_PSK_WITH_NULL_SHA256 = 0xc03a
    case TLS_ECDHE_PSK_WITH_NULL_SHA384 = 0xc03b
    case TLS_RSA_WITH_ARIA_128_CBC_SHA256 = 0xc03c
    case TLS_RSA_WITH_ARIA_256_CBC_SHA384 = 0xc03d
    case TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 = 0xc03e
    case TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 = 0xc03f
    case TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 = 0xc040
    case TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 = 0xc041
    case TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 = 0xc042
    case TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 = 0xc043
    case TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 = 0xc044
    case TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 = 0xc045
    case TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 = 0xc046
    case TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 = 0xc047
    case TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 = 0xc048
    case TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 = 0xc049
    case TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 = 0xc04a
    case TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 = 0xc04b
    case TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 = 0xc04c
    case TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 = 0xc04d
    case TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 = 0xc04e
    case TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 = 0xc04f
    case TLS_RSA_WITH_ARIA_128_GCM_SHA256 = 0xc050
    case TLS_RSA_WITH_ARIA_256_GCM_SHA384 = 0xc051
    case TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 = 0xc052
    case TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 = 0xc053
    case TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 = 0xc054
    case TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 = 0xc055
    case TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 = 0xc056
    case TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 = 0xc057
    case TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 = 0xc058
    case TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 = 0xc059
    case TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 = 0xc05a
    case TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 = 0xc05b
    case TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 = 0xc05c
    case TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 = 0xc05d
    case TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 = 0xc05e
    case TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 = 0xc05f
    case TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 = 0xc060
    case TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 = 0xc061
    case TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 = 0xc062
    case TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 = 0xc063
    case TLS_PSK_WITH_ARIA_128_CBC_SHA256 = 0xc064
    case TLS_PSK_WITH_ARIA_256_CBC_SHA384 = 0xc065
    case TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 = 0xc066
    case TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 = 0xc067
    case TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 = 0xc068
    case TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 = 0xc069
    case TLS_PSK_WITH_ARIA_128_GCM_SHA256 = 0xc06a
    case TLS_PSK_WITH_ARIA_256_GCM_SHA384 = 0xc06b
    case TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 = 0xc06c
    case TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 = 0xc06d
    case TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 = 0xc06e
    case TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 = 0xc06f
    case TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 = 0xc070
    case TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 = 0xc071
    case TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xc072
    case TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xc073
    case TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xc074
    case TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xc075
    case TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xc076
    case TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xc077
    case TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xc078
    case TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xc079
    case TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc07a
    case TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc07b
    case TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc07c
    case TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc07d
    case TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc07e
    case TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc07f
    case TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 = 0xc080
    case TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 = 0xc081
    case TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 = 0xc082
    case TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 = 0xc083
    case TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 = 0xc084
    case TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 = 0xc085
    case TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc086
    case TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc087
    case TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc088
    case TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc089
    case TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc08a
    case TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc08b
    case TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc08c
    case TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc08d
    case TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xc08e
    case TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xc08f
    case TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xc090
    case TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xc091
    case TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xc092
    case TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xc093
    case TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xc094
    case TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xc095
    case TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xc096
    case TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xc097
    case TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xc098
    case TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xc099
    case TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xc09a
    case TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xc09b
    case TLS_RSA_WITH_AES_128_CCM = 0xc09c
    case TLS_RSA_WITH_AES_256_CCM = 0xc09d
    case TLS_DHE_RSA_WITH_AES_128_CCM = 0xc09e
    case TLS_DHE_RSA_WITH_AES_256_CCM = 0xc09f
    case TLS_RSA_WITH_AES_128_CCM_8 = 0xc0a0
    case TLS_RSA_WITH_AES_256_CCM_8 = 0xc0a1
    case TLS_DHE_RSA_WITH_AES_128_CCM_8 = 0xc0a2
    case TLS_DHE_RSA_WITH_AES_256_CCM_8 = 0xc0a3
    case TLS_PSK_WITH_AES_128_CCM = 0xc0a4
    case TLS_PSK_WITH_AES_256_CCM = 0xc0a5
    case TLS_DHE_PSK_WITH_AES_128_CCM = 0xc0a6
    case TLS_DHE_PSK_WITH_AES_256_CCM = 0xc0a7
    case TLS_PSK_WITH_AES_128_CCM_8 = 0xc0a8
    case TLS_PSK_WITH_AES_256_CCM_8 = 0xc0a9
    case TLS_PSK_DHE_WITH_AES_128_CCM_8 = 0xc0aa
    case TLS_PSK_DHE_WITH_AES_256_CCM_8 = 0xc0ab
    case TLS_ECDHE_ECDSA_WITH_AES_128_CCM = 0xc0ac
    case TLS_ECDHE_ECDSA_WITH_AES_256_CCM = 0xc0ad
    case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0xc0ae
    case TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = 0xc0af

    // mandatory cipher suite to be TLS compliant as of RFC 2246
//    case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
    
    func needsServerKeyExchange() -> Bool {
        
        let keyExchangeAlgorithm = TLSCipherSuiteDescriptorForCipherSuite(self).keyExchangeAlgorithm

        switch keyExchangeAlgorithm
        {
        case .DHE_RSA:
            return true
            
        default:
            return false
        }
    }
}


public enum CompressionMethod : UInt8 {
    case NULL = 0
}



enum TLSContextState
{
    case Idle
    case ClientHelloSent
    case ClientHelloReceived
    case ServerHelloSent
    case ServerHelloReceived
    case ServerCertificateSent
    case ServerCertificateReceived
    case ServerKeyExchangeSent
    case ServerKeyExchangeReceived
    case ServerHelloDoneSent
    case ServerHelloDoneReceived
    case ClientCertificateSent
    case ClientCertificateReceived
    case ClientKeyExchangeSent
    case ClientKeyExchangeReceived
    case ChangeCipherSpecSent
    case ChangeCipherSpecReceived
    case FinishedSent
    case FinishedReceived
    case Connected
    case CloseSent
    case CloseReceived
    case Error
}



enum TLSError : ErrorType
{
    case Error
}


enum TLSDataProviderError : ErrorType
{
    init?(socketError : SocketError?)
    {
        if let error = socketError {
            switch error {
            case .PosixError(let errno):
                self = TLSDataProviderError.PosixError(errno: errno)
            }
        }
        else {
            return nil
        }
    }
    
    case PosixError(errno : Int32)
}

extension TLSDataProviderError : CustomStringConvertible
{
    var description : String {
        get {
            switch (self)
            {
            case let .PosixError(errno):
                return String.fromCString(strerror(errno))!
            }
        }
    }
}



protocol TLSDataProvider : class
{
    func writeData(data : [UInt8], completionBlock : ((TLSDataProviderError?) -> ())?)
    func readData(count count : Int, completionBlock : ((data : [UInt8]?, error : TLSDataProviderError?) -> ()))
}

let TLSClientFinishedLabel = [UInt8]("client finished".utf8)
let TLSServerFinishedLabel = [UInt8]("server finished".utf8)

enum ConnectionEnd {
    case Client
    case Server
}

enum CipherType {
    case Block
    case Stream
}

enum BlockCipherMode {
    case CBC
}

enum MACAlgorithm {
    case HMAC_MD5
    case HMAC_SHA1
    case HMAC_SHA256
    case HMAC_SHA384
    case HMAC_SHA512
}

enum CipherAlgorithm
{
    case NULL
    case TRIPLE_DES
    case AES
}

enum KeyExchangeAlgorithm
{
    case RSA
    case DHE_RSA
}

enum PRFAlgorithm {
    case PRF_TLS_1_0
}



class TLSSecurityParameters
{
    var                     connectionEnd : ConnectionEnd = .Client
    var                     prfAlgorithm : PRFAlgorithm = .PRF_TLS_1_0
    var                     bulkCipherAlgorithm : CipherAlgorithm? = nil
    var                     cipherType : CipherType? = nil
    var                     encodeKeyLength : Int = 0
    var                     blockLength : Int = 0
    var                     fixedIVLength : Int = 0
    var                     recordIVLength : Int = 0
    var                     hmacDescriptor : HMACDescriptor? = nil
    var                     masterSecret : [UInt8]? = nil
    var                     clientRandom : [UInt8]? = nil
    var                     serverRandom : [UInt8]? = nil
    
    // Calculate master secret as described in RFC 2246, section 8.1, p. 46
    func calculateMasterSecret(preMasterSecret : [UInt8])
    {
        self.masterSecret = PRF(secret: preMasterSecret, label: [UInt8]("master secret".utf8), seed: self.clientRandom! + self.serverRandom!, outputLength: 48)
        print("master secret: \(hex(self.masterSecret!))")
    }
}



public class TLSContext
{
    var protocolVersion : TLSProtocolVersion
    var negotiatedProtocolVersion : TLSProtocolVersion! = nil
    public var cipherSuites : [CipherSuite]?
    
    var cipherSuite : CipherSuite?
    
    var state : TLSContextState = .Idle {
        willSet {
            if !checkStateTransition(newValue) {
                fatalError("Illegal state transition")
            }
        }
    }
    
    var serverKey : CryptoKey?
    var clientKey : CryptoKey?
    
    var identity : Identity?
    
    var serverCertificates : [Certificate]?
    var clientCertificates : [Certificate]?
    
    var preMasterSecret     : [UInt8]? = nil {
        didSet {
            print("pre master secret = \(hex(preMasterSecret!))")
        }
    }

    var securityParameters  : TLSSecurityParameters
    
    var handshakeMessages : [TLSHandshakeMessage]
    
    let isClient : Bool
    
    var recordLayer : TLSRecordLayer!
    
    var dhKeyExchange : DiffieHellmanKeyExchange?
    
    private var connectionEstablishedCompletionBlock : ((error : TLSError?) -> ())?
    
    init(protocolVersion: TLSProtocolVersion, dataProvider : TLSDataProvider, isClient : Bool = true)
    {
        self.protocolVersion = protocolVersion
        self.isClient = isClient

        self.handshakeMessages = []
        
        self.securityParameters = TLSSecurityParameters()
        
        self.cipherSuites = [.TLS_RSA_WITH_AES_256_CBC_SHA]
        
        self.recordLayer = TLSRecordLayer(context: self, dataProvider: dataProvider)
    }
    
    func copy() -> TLSContext
    {
        let context = TLSContext(protocolVersion: self.protocolVersion, dataProvider: self.recordLayer.dataProvider!, isClient: self.isClient)
        
        context.cipherSuites = self.cipherSuites
        context.cipherSuite = self.cipherSuite
        
        context.serverKey = self.serverKey
        context.clientKey = self.clientKey
        context.identity = self.identity
        
        context.serverCertificates = self.serverCertificates
        context.clientCertificates = self.clientCertificates
        
        
        if let preMasterSecret = self.preMasterSecret {
            context.preMasterSecret = preMasterSecret
        }
        
        context.securityParameters = self.securityParameters
        
        context.handshakeMessages = self.handshakeMessages

        return context
    }
    
    func startConnection(completionBlock : (error : TLSError?) -> ())
    {
        self.connectionEstablishedCompletionBlock = completionBlock
        
        self.sendClientHello()
        self.state = .ClientHelloSent
        
        self.receiveNextTLSMessage(completionBlock)
    }
    
    func acceptConnection(completionBlock : (error : TLSError?) -> ())
    {
        self.connectionEstablishedCompletionBlock = completionBlock

        self.receiveNextTLSMessage(completionBlock)
    }
    
    func sendApplicationData(data : [UInt8], completionBlock : ((TLSDataProviderError?) -> ())? = nil)
    {
        self.recordLayer.sendData(contentType: .ApplicationData, data: data, completionBlock: completionBlock)
    }
    
    func sendMessage(message : TLSMessage, completionBlock : ((TLSDataProviderError?) -> ())? = nil)
    {
        self.recordLayer.sendMessage(message, completionBlock: completionBlock)
        self.didSendMessage(message)
    }
    
    func sendAlert(alert : TLSAlert, alertLevel : TLSAlertLevel, completionBlock : ((TLSDataProviderError?) -> ())? = nil)
    {
        let alertMessage = TLSAlertMessage(alert: alert, alertLevel: alertLevel)
        self.recordLayer.sendMessage(alertMessage, completionBlock: completionBlock)
    }
    
    private func sendHandshakeMessage(message : TLSHandshakeMessage, completionBlock : ((TLSDataProviderError?) -> ())? = nil)
    {
        self.sendMessage(message, completionBlock: completionBlock)
        
        self.handshakeMessages.append(message)
    }
    
    func didSendMessage(message : TLSMessage)
    {
        print((self.isClient ? "Client" : "Server" ) + ": did send message \(TLSMessageNameForType(message.type))")
    }
    
    func didSendHandshakeMessage(message : TLSHandshakeMessage)
    {
    }
    
    func didReceiveHandshakeMessage(message : TLSHandshakeMessage)
    {
        if let clientHello = message as? TLSClientHello {
            print("TLS version: \(clientHello.clientVersion)")
            print("Supported Cipher Suites:")
            for cipherSuite in clientHello.cipherSuites {
                print("\(cipherSuite)")
            }
        }
    }
    
    func _didReceiveMessage(message : TLSMessage, completionBlock: ((TLSError?) -> ())?)
    {
        print((self.isClient ? "Client" : "Server" ) + ": did receive message \(TLSMessageNameForType(message.type))")

        switch (message.type)
        {
        case .ChangeCipherSpec:
            self.state = .ChangeCipherSpecReceived
            
            self.recordLayer.activateReadEncryptionParameters()
            
            self.receiveNextTLSMessage(completionBlock)
            
            break
            
        case .Handshake:
            let handshakeMessage = message as! TLSHandshakeMessage
            self._didReceiveHandshakeMessage(handshakeMessage, completionBlock: completionBlock)

        case .Alert:
            break
            
        case .ApplicationData:
            break
        }
    }

    func _didReceiveHandshakeMessage(message : TLSHandshakeMessage, completionBlock: ((TLSError?) -> ())?)
    {
        let tlsConnectCompletionBlock = completionBlock

        SWITCH: switch (message.type)
        {
        case .Handshake(let handshakeType):
            
            if (handshakeType != .Finished) {
                // don't add the incoming Finished message to handshakeMessages.
                // We need to verify it's data against the handshake messages before it.
                self.handshakeMessages.append(message)
            }
            
            switch (handshakeType)
            {
            case .ClientHello:
                let clientHello = (message as! TLSClientHello)
                self.securityParameters.clientRandom = DataBuffer(clientHello.random).buffer
                
                self.cipherSuite = self.selectCipherSuite(clientHello.cipherSuites)
                
                if let _ = self.cipherSuite {
                    self.sendServerHello()
                    self.state = .ServerHelloSent
                    
                    self.sendCertificate()
                    self.state = .ServerCertificateSent
                    
                    self.sendServerHelloDone()
                    self.state = .ServerHelloDoneSent
                }
                else {
                    self.sendAlert(.HandshakeFailure, alertLevel: .Fatal, completionBlock: nil)
                }

            case .ServerHello:
                self.state = .ServerHelloReceived
                let serverHello = message as! TLSServerHello
                let version = serverHello.version
                print("Server wants to speak \(version)")
                
                self.recordLayer.protocolVersion = version
                
                self.cipherSuite = serverHello.cipherSuite
                self.securityParameters.serverRandom = DataBuffer(serverHello.random).buffer
                if !serverHello.cipherSuite.needsServerKeyExchange()
                {
                    self.preMasterSecret = DataBuffer(PreMasterSecret(clientVersion: self.protocolVersion)).buffer
                    self.setPendingSecurityParametersForCipherSuite(serverHello.cipherSuite)
                    self.recordLayer.pendingSecurityParameters = self.securityParameters
                }
            
            case .Certificate:
                self.state = isClient ? .ServerCertificateReceived : .ClientCertificateReceived
                let certificateMessage = message as! TLSCertificateMessage
                self.serverCertificates = certificateMessage.certificates
                self.serverKey = certificateMessage.publicKey

            case .ServerKeyExchange:
                self.state = .ServerKeyExchangeReceived
                
                let keyExchangeMessage = message as! TLSServerKeyExchange
                
                let p = BigInt(keyExchangeMessage.dh_p.reverse())
                let g = BigInt(keyExchangeMessage.dh_g.reverse())
                let Ys = BigInt(keyExchangeMessage.dh_Ys.reverse())

                let dhKeyExchange = DiffieHellmanKeyExchange(primeModulus: p, generator: g)
                dhKeyExchange.peerPublicValue = Ys
                self.dhKeyExchange = dhKeyExchange
                
            case .ServerHelloDone:
                self.state = .ServerHelloDoneReceived

                self.sendClientKeyExchange()
                self.state = .ClientKeyExchangeSent
                
                self.sendChangeCipherSpec()
                self.state = .ChangeCipherSpecSent

                self.sendFinished()
                self.state = .FinishedSent
                
            case .ClientKeyExchange:
                self.state = .ClientKeyExchangeReceived
                
                let clientKeyExchange = message as! TLSClientKeyExchange
                if let dhKeyExchange = self.dhKeyExchange {
                    // Diffie-Hellman
                    if let diffieHellmanPublicValue = clientKeyExchange.diffieHellmanPublicValue {
                        let secret = BigInt.random(dhKeyExchange.primeModulus)
                        dhKeyExchange.peerPublicValue = BigInt(diffieHellmanPublicValue.reverse())
                        self.preMasterSecret = BigIntImpl<UInt8>(dhKeyExchange.calculateSharedSecret(secret)!).parts.reverse()
                    }
                    else {
                        fatalError("Client Key Exchange has no encrypted master secret")
                    }
                }
                else {
                    // RSA
                    if let encryptedPreMasterSecret = clientKeyExchange.encryptedPreMasterSecret {
                        self.preMasterSecret = self.identity!.privateKey.decrypt(encryptedPreMasterSecret)
                    }
                    else {
                        fatalError("Client Key Exchange has no encrypted master secret")
                    }
                }
                
                
                self.setPendingSecurityParametersForCipherSuite(self.cipherSuite!)
                self.recordLayer.pendingSecurityParameters = self.securityParameters

            case .Finished:
                self.state = .FinishedReceived

                if (self.verifyFinishedMessage(message as! TLSFinished, isClient: !self.isClient)) {
                    print((self.isClient ? "Client" : "Server" ) + ": Finished verified.")
                    
                    if !self.isClient {
                        self.sendChangeCipherSpec()
                        self.state = .ChangeCipherSpecSent
                        
                        self.handshakeMessages.append(message)
                        
                        self.sendFinished()
                        self.state = .FinishedSent
                    }
                    
                    if let connectionEstablishedBlock = self.connectionEstablishedCompletionBlock {
                        connectionEstablishedBlock(error: nil)
                    }
                }
                else {
                    print("Error: could not verify Finished message.")
                }
                
            default:
                print("unsupported handshake \(handshakeType.rawValue)")
                if let block = tlsConnectCompletionBlock {
                    block(TLSError.Error)
                }
            }
            
        default:
            print("unsupported handshake \(message.type)")
            if let block = tlsConnectCompletionBlock {
                block(TLSError.Error)

                break SWITCH
            }
        }
        
        self.didReceiveHandshakeMessage(message)
        
        switch (message.type)
        {
        case .Handshake(let handshakeType):
            if handshakeType != .Finished {
                self.receiveNextTLSMessage(completionBlock)
            }
            
        default:
            break
        }
    }
    
    func sendClientHello()
    {
        let clientHelloRandom = Random()
        let clientHello = TLSClientHello(
            clientVersion: self.protocolVersion,
            random: clientHelloRandom,
            sessionID: nil,
            cipherSuites: self.cipherSuites!,
//            cipherSuites: [.TLS_RSA_WITH_NULL_SHA],
            compressionMethods: [.NULL])
        
        self.securityParameters.clientRandom = DataBuffer(clientHelloRandom).buffer
        self.sendHandshakeMessage(clientHello)
    }
    
    func sendServerHello()
    {
        let serverHelloRandom = Random()
        let serverHello = TLSServerHello(
            serverVersion: self.protocolVersion,
            random: serverHelloRandom,
            sessionID: nil,
            cipherSuite: self.cipherSuite!,
            compressionMethod: .NULL)
        
        self.securityParameters.serverRandom = DataBuffer(serverHelloRandom).buffer
        self.sendHandshakeMessage(serverHello)
    }
    
    func sendCertificate()
    {
        let certificate = self.identity!.certificate
        let certificateMessage = TLSCertificateMessage(certificates: [certificate])
        
        self.sendHandshakeMessage(certificateMessage);
    }
    
    func sendServerHelloDone()
    {
        self.sendHandshakeMessage(TLSServerHelloDone())
    }
    
    func sendClientKeyExchange()
    {
        if let diffieHellmanKeyExchange = self.dhKeyExchange {
            // Diffie-Hellman
            let secret = BigInt.random(diffieHellmanKeyExchange.primeModulus)
            let publicValue = diffieHellmanKeyExchange.calculatePublicValue(secret)
            let sharedSecret = diffieHellmanKeyExchange.calculateSharedSecret(secret)!
            self.preMasterSecret = BigIntImpl<UInt8>(sharedSecret).parts.reverse()
            self.setPendingSecurityParametersForCipherSuite(self.cipherSuite!)
            self.recordLayer.pendingSecurityParameters = self.securityParameters

            let message = TLSClientKeyExchange(diffieHellmanPublicValue: BigIntImpl<UInt8>(publicValue).parts.reverse())
            self.sendHandshakeMessage(message)
        }
        else {
            if let serverKey = self.serverKey {
                // RSA
                let message = TLSClientKeyExchange(preMasterSecret: self.preMasterSecret!, publicKey: serverKey)
                self.sendHandshakeMessage(message)
            }
        }
    }

    func sendChangeCipherSpec()
    {
        let message = TLSChangeCipherSpec()
        
        self.sendMessage(message)

        self.recordLayer.activateWriteEncryptionParameters()
    }
    
    func sendFinished()
    {
        let verifyData = self.verifyDataForFinishedMessage(isClient: self.isClient)
        self.sendHandshakeMessage(TLSFinished(verifyData: verifyData), completionBlock: nil)
    }

    private func verifyFinishedMessage(finishedMessage : TLSFinished, isClient: Bool) -> Bool
    {
        let verifyData = self.verifyDataForFinishedMessage(isClient: isClient)
        
        return finishedMessage.verifyData == verifyData
    }

    private func verifyDataForFinishedMessage(isClient isClient: Bool) -> [UInt8]
    {
        let finishedLabel = isClient ? TLSClientFinishedLabel : TLSServerFinishedLabel
        
        var handshakeData = [UInt8]()
        for message in self.handshakeMessages {
            if let messageData = message.rawHandshakeMessageData {
                handshakeData.appendContentsOf(messageData)
            }
            else {
                var messageBuffer = DataBuffer()
                message.writeTo(&messageBuffer)
                
                handshakeData.appendContentsOf(messageBuffer.buffer)
            }
        }
        
        let clientHandshakeMD5  = Hash_MD5(handshakeData)
        let clientHandshakeSHA1 = Hash_SHA1(handshakeData)
        
        let d = clientHandshakeMD5 + clientHandshakeSHA1

        let verifyData = PRF(secret: self.securityParameters.masterSecret!, label: finishedLabel, seed: d, outputLength: 12)
        
        return verifyData
    }
    
    
    private func receiveNextTLSMessage(completionBlock: ((TLSError?) -> ())?)
    {
//        let tlsConnectCompletionBlock = completionBlock
        
        self._readTLSMessage {
            (message : TLSMessage?) -> () in
            
            if let m = message {
                self._didReceiveMessage(m, completionBlock: completionBlock)
            }
        }
    }

    func readTLSMessage(completionBlock: (message : TLSMessage?) -> ())
    {
        self._readTLSMessage(completionBlock)
    }
    
    private func _readTLSMessage(completionBlock: (message : TLSMessage?) -> ())
    {
        self.recordLayer.readMessage(completionBlock: completionBlock)
    }
    
    private func setPendingSecurityParametersForCipherSuite(cipherSuite : CipherSuite)
    {
        let cipherSuiteDescriptor = TLSCipherSuiteDescriptorForCipherSuite(cipherSuite)
        let cipherAlgorithmDescriptor = cipherSuiteDescriptor.bulkCipherAlgorithm

        self.securityParameters.bulkCipherAlgorithm  = cipherAlgorithmDescriptor.algorithm
        self.securityParameters.encodeKeyLength      = cipherAlgorithmDescriptor.keySize
        self.securityParameters.blockLength          = cipherAlgorithmDescriptor.blockSize
        self.securityParameters.fixedIVLength        = cipherAlgorithmDescriptor.blockSize
        self.securityParameters.recordIVLength       = cipherAlgorithmDescriptor.blockSize
        self.securityParameters.hmacDescriptor       = cipherSuiteDescriptor.hmacDescriptor
        
        self.securityParameters.calculateMasterSecret(self.preMasterSecret!)
    }
    
    func advanceState(state : TLSContextState) -> Bool
    {
        if checkStateTransition(state) {
            self.state = state
            
            return true
        }
        
        return false
    }
    
    
    func checkClientStateTransition(state : TLSContextState) -> Bool
    {
        switch (self.state)
        {
        case .Idle where state == .ClientHelloSent:
            return true
            
        case .ClientHelloSent where state == .ServerHelloReceived:
            return true
            
        case .ServerHelloReceived where state == .ServerCertificateReceived:
            return true
            
        case .ServerCertificateReceived:
            if self.cipherSuite!.needsServerKeyExchange() {
                if state == .ServerKeyExchangeReceived {
                    return true
                }
            }
            else if state == .ServerHelloDoneReceived {
                return true
            }
            
        case .ServerKeyExchangeReceived where state == .ServerHelloDoneReceived:
            return true
            
        case .ServerHelloDoneReceived where state == .ClientKeyExchangeSent:
            return true
            
        case .ClientKeyExchangeSent where state == .ChangeCipherSpecSent:
            return true
            
        case .ChangeCipherSpecSent where state == .FinishedSent:
            return true
            
        case .FinishedSent where state == .ChangeCipherSpecReceived:
            return true
            
        case .ChangeCipherSpecReceived where state == .FinishedReceived:
            return true

        case .FinishedReceived where state == .Connected:
            return true
            
        case .Connected where (state == .CloseReceived || state == .CloseSent):
            return true
            
        default:
            return false
        }
        
        return false
    }
    
    func checkServerStateTransition(state : TLSContextState) -> Bool
    {
        switch (self.state)
        {
        case .Idle where state == .ServerHelloSent:
            return true

        case .ServerHelloSent where state == .ServerCertificateSent:
            return true

        case .ServerCertificateSent:
            if self.cipherSuite!.needsServerKeyExchange() {
                if state == .ServerKeyExchangeSent {
                    return true
                }
            }
            else if state == .ServerHelloDoneSent {
                return true
            }

        case .ServerKeyExchangeSent where state == .ServerHelloDoneSent:
            return true
            
        case .ServerHelloDoneSent where state == .ClientKeyExchangeReceived:
            return true

        case .ClientKeyExchangeReceived where state == .ChangeCipherSpecReceived:
            return true

        case .ChangeCipherSpecReceived where state == .FinishedReceived:
            return true

        case .FinishedReceived where state == .ChangeCipherSpecSent:
            return true

        case .ChangeCipherSpecSent where state == .FinishedSent:
            return true

        case .FinishedSent where state == .Connected:
            return true

        default:
            return false
        }
        
        return false
    }
    
    func checkStateTransition(state : TLSContextState) -> Bool
    {
        if self.isClient {
            return checkClientStateTransition(state)
        }
        else {
            return checkServerStateTransition(state)
        }
    }
    
    func selectCipherSuite(cipherSuites : [CipherSuite]) -> CipherSuite?
    {
        for clientCipherSuite in cipherSuites {
            for myCipherSuite in self.cipherSuites! {
                if clientCipherSuite == myCipherSuite {
                    return myCipherSuite
                }
            }
        }
        
        return nil
    }
}
