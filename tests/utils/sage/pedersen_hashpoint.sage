##*************************************************************************************/
##/* Copyright (C) 2022 - Renaud Dubois - This file is part of cy_lib project	 */
##/* License: This software is licensed under a dual BSD and GPL v2 license. 	 */
##/* See LICENSE file at the root folder of the project.				 */
##/* FILE: musig2.sage							         */
##/* 											 */
##/* 											 */
##/* DESCRIPTION: Pedersen Hash modified Stark version as coded in */
##/* https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/crypto/signature/fast_pedersen_hash.py
##/* spec is here:https://docs.starkware.co/starkex/pedersen-hash-function.html
##/source code 		 */
##/**************************************************************************************/


PEDERSEN_SHIFT = [##shift = constant[0]
   0x49ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804,
   0x3ca0cfe4b3bc6ddf346d49d06ea0ed34e621062c0e056c1d0405d266e10268a	
];

PEDERSEN_POINTS=[
        [##P0 = constant[2]
            0x234287dcbaffe7f969c748655fca9e58fa8120b6d56eb0c1080d17957ebe47b,
            0x3b056f100f96fb21e889527d41f4e39940135dd7a6c94cc6ed0268ee89e5615
        ],
        [##P1
            0x04fa56f376c83db33f9dab2656558f3399099ec1de5e3018b7a6932dba8aa378,
            0x03fa0984c931c9e38113e0c0e47e4401562761f92a7a23b45168f4e80ff5b54d
        ],
        [##P2
          0x04ba4cc166be8dec764910f75b45f74b40c690c74709e90f3aa372f0bd2d6997,        
          0x0040301cf5c1751f4b971e46c4ede85fcac5c59a5ce5ae7c48151f27b24b219c
        ],
        [##P3
          0x054302dcb0e6cc1c6e44cca8f61a63bb2ca65048d53fb325d36ff12c49a58202,
          0x01b77b3e37d13504b348046268d8ae25ce98ad783c25561a879dcc77e99c2426
        ]
    ];
    

def Init_Stark(curve_characteristic,curve_a, curve_b,Gx, Gy, curve_Order):    
	Fp=GF(curve_characteristic); 				#Initialize Prime field of Point
	Fq=GF(curve_Order);					#Initialize Prime field of scalars
	Curve=EllipticCurve(Fp, [curve_a, curve_b]);		#Initialize Elliptic curve
	curve_Generator=Curve([Gx, Gy]);
	P0=Curve([PEDERSEN_POINTS[0][0], PEDERSEN_POINTS[0][1]]);
	P1=Curve([PEDERSEN_POINTS[1][0], PEDERSEN_POINTS[1][1]]);
	P2=Curve([PEDERSEN_POINTS[2][0], PEDERSEN_POINTS[2][1]]);
	P3=Curve([PEDERSEN_POINTS[3][0], PEDERSEN_POINTS[3][1]]);
	Shift=Curve(PEDERSEN_SHIFT[0], PEDERSEN_SHIFT[1]);
	return [Curve,curve_Generator, P0, P1, P2, P3, Shift];
	

def  pedersen_point(a,b):
	hi_a=a>>248;
	low_a =a&(2^248-1);
	hi_b=b>>248;
	low_b =b&(2^248-1);
	HashPoint=Shift+low_a*P0+hi_a*P1+low_b*P2+hi_b*P3;
	
	return HashPoint;
	
def  pedersen(a,b):
	hi_a=a>>248;
	low_a =a&(2^248-1);
	hi_b=b>>248;
	low_b =b&(2^248-1);
	HashPoint=Shift+low_a*P0+hi_a*P1+low_b*P2+hi_b*P3;
	
	return int(HashPoint[0]);

# one shot implementation of Starknet chain of hash:
# hash of sequence (x, y, ..., xn) is h(h(h(h(0, x1), x2), ...), n)
# as described in source code :cairo-lang/src/starkware/cairo/common/hash_state.cairo 

def pedersen_hash(data, data_feltlength):
	hash=pedersen(0, data[0]); 			#h(0,x1)
	for i in [1..data_feltlength-1]:		#intermediate hashes
		hash=pedersen(hash, data[i]);		
	hash=pedersen(hash,data_feltlength);		#length of hash data is appended to avoid collision with lesser height			 		
	
	return hash;

# not tested yet
# Kpub point of the Curve representing the public key
# note:r,s, hash provided as integers
def ecdsa_verif(Curve, curve_generator, curve_order, Kpub, r, s, hash):
	Fq=GF(curve_order);
	e=Fq(hash);
	
	u1=e*s^-1;
	u2=r*s^-1;
	R=u1*curve_generator+u2*Kpub;
	return int(R[0])==r;
	





	
