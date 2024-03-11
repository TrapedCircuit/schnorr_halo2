
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

contract Halo2Verifier {
    fallback(bytes calldata) external returns (bytes memory) {
        assembly ("memory-safe") {
            // Enforce that Solidity memory layout is respected
            let data := mload(0x40)
            if iszero(eq(data, 0x80)) {
                revert(0, 0)
            }

            let success := true
            let f_p := 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
            let f_q := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
            function validate_ec_point(x, y) -> valid {
                {
                    let x_lt_p := lt(x, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                    let y_lt_p := lt(y, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                    valid := and(x_lt_p, y_lt_p)
                }
                {
                    let y_square := mulmod(y, y, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                    let x_square := mulmod(x, x, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                    let x_cube := mulmod(x_square, x, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                    let x_cube_plus_3 := addmod(x_cube, 3, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                    let is_affine := eq(x_cube_plus_3, y_square)
                    valid := and(valid, is_affine)
                }
            }
            mstore(0x80, 74661503438511888870482592890660317929356101195553119667558287640603733369)

        {
            let x := calldataload(0x0)
            mstore(0xa0, x)
            let y := calldataload(0x20)
            mstore(0xc0, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0xe0, keccak256(0x80, 96))
{
            let hash := mload(0xe0)
            mstore(0x100, mod(hash, f_q))
            mstore(0x120, hash)
        }

        {
            let x := calldataload(0x40)
            mstore(0x140, x)
            let y := calldataload(0x60)
            mstore(0x160, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x80)
            mstore(0x180, x)
            let y := calldataload(0xa0)
            mstore(0x1a0, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0x1c0, keccak256(0x120, 160))
{
            let hash := mload(0x1c0)
            mstore(0x1e0, mod(hash, f_q))
            mstore(0x200, hash)
        }
mstore8(544, 1)
mstore(0x220, keccak256(0x200, 33))
{
            let hash := mload(0x220)
            mstore(0x240, mod(hash, f_q))
            mstore(0x260, hash)
        }

        {
            let x := calldataload(0xc0)
            mstore(0x280, x)
            let y := calldataload(0xe0)
            mstore(0x2a0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x100)
            mstore(0x2c0, x)
            let y := calldataload(0x120)
            mstore(0x2e0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x140)
            mstore(0x300, x)
            let y := calldataload(0x160)
            mstore(0x320, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0x340, keccak256(0x260, 224))
{
            let hash := mload(0x340)
            mstore(0x360, mod(hash, f_q))
            mstore(0x380, hash)
        }

        {
            let x := calldataload(0x180)
            mstore(0x3a0, x)
            let y := calldataload(0x1a0)
            mstore(0x3c0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x1c0)
            mstore(0x3e0, x)
            let y := calldataload(0x1e0)
            mstore(0x400, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x200)
            mstore(0x420, x)
            let y := calldataload(0x220)
            mstore(0x440, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x240)
            mstore(0x460, x)
            let y := calldataload(0x260)
            mstore(0x480, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0x4a0, keccak256(0x380, 288))
{
            let hash := mload(0x4a0)
            mstore(0x4c0, mod(hash, f_q))
            mstore(0x4e0, hash)
        }
mstore(0x500, mod(calldataload(0x280), f_q))
mstore(0x520, mod(calldataload(0x2a0), f_q))
mstore(0x540, mod(calldataload(0x2c0), f_q))
mstore(0x560, mod(calldataload(0x2e0), f_q))
mstore(0x580, mod(calldataload(0x300), f_q))
mstore(0x5a0, mod(calldataload(0x320), f_q))
mstore(0x5c0, mod(calldataload(0x340), f_q))
mstore(0x5e0, mod(calldataload(0x360), f_q))
mstore(0x600, mod(calldataload(0x380), f_q))
mstore(0x620, mod(calldataload(0x3a0), f_q))
mstore(0x640, mod(calldataload(0x3c0), f_q))
mstore(0x660, mod(calldataload(0x3e0), f_q))
mstore(0x680, mod(calldataload(0x400), f_q))
mstore(0x6a0, mod(calldataload(0x420), f_q))
mstore(0x6c0, mod(calldataload(0x440), f_q))
mstore(0x6e0, mod(calldataload(0x460), f_q))
mstore(0x700, mod(calldataload(0x480), f_q))
mstore(0x720, mod(calldataload(0x4a0), f_q))
mstore(0x740, keccak256(0x4e0, 608))
{
            let hash := mload(0x740)
            mstore(0x760, mod(hash, f_q))
            mstore(0x780, hash)
        }
mstore8(1952, 1)
mstore(0x7a0, keccak256(0x780, 33))
{
            let hash := mload(0x7a0)
            mstore(0x7c0, mod(hash, f_q))
            mstore(0x7e0, hash)
        }

        {
            let x := calldataload(0x4c0)
            mstore(0x800, x)
            let y := calldataload(0x4e0)
            mstore(0x820, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0x840, keccak256(0x7e0, 96))
{
            let hash := mload(0x840)
            mstore(0x860, mod(hash, f_q))
            mstore(0x880, hash)
        }

        {
            let x := calldataload(0x500)
            mstore(0x8a0, x)
            let y := calldataload(0x520)
            mstore(0x8c0, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0x8e0, mulmod(mload(0x4c0), mload(0x4c0), f_q))
mstore(0x900, mulmod(mload(0x8e0), mload(0x8e0), f_q))
mstore(0x920, mulmod(mload(0x900), mload(0x900), f_q))
mstore(0x940, mulmod(mload(0x920), mload(0x920), f_q))
mstore(0x960, mulmod(mload(0x940), mload(0x940), f_q))
mstore(0x980, mulmod(mload(0x960), mload(0x960), f_q))
mstore(0x9a0, mulmod(mload(0x980), mload(0x980), f_q))
mstore(0x9c0, mulmod(mload(0x9a0), mload(0x9a0), f_q))
mstore(0x9e0, mulmod(mload(0x9c0), mload(0x9c0), f_q))
mstore(0xa00, mulmod(mload(0x9e0), mload(0x9e0), f_q))
mstore(0xa20, mulmod(mload(0xa00), mload(0xa00), f_q))
mstore(0xa40, mulmod(mload(0xa20), mload(0xa20), f_q))
mstore(0xa60, mulmod(mload(0xa40), mload(0xa40), f_q))
mstore(0xa80, mulmod(mload(0xa60), mload(0xa60), f_q))
mstore(0xaa0, mulmod(mload(0xa80), mload(0xa80), f_q))
mstore(0xac0, mulmod(mload(0xaa0), mload(0xaa0), f_q))
mstore(0xae0, mulmod(mload(0xac0), mload(0xac0), f_q))
mstore(0xb00, mulmod(mload(0xae0), mload(0xae0), f_q))
mstore(0xb20, mulmod(mload(0xb00), mload(0xb00), f_q))
mstore(0xb40, mulmod(mload(0xb20), mload(0xb20), f_q))
mstore(0xb60, addmod(mload(0xb40), 21888242871839275222246405745257275088548364400416034343698204186575808495616, f_q))
mstore(0xb80, mulmod(mload(0xb60), 21888221997584217086951279548962733484243966294447177135413498358668068307201, f_q))
mstore(0xba0, mulmod(mload(0xb80), 3021657639704125634180027002055603444074884651778695243656177678924693902744, f_q))
mstore(0xbc0, addmod(mload(0x4c0), 18866585232135149588066378743201671644473479748637339100042026507651114592873, f_q))
mstore(0xbe0, mulmod(mload(0xb80), 13315224328250071823986980334210714047804323884995968263773489477577155309695, f_q))
mstore(0xc00, addmod(mload(0x4c0), 8573018543589203398259425411046561040744040515420066079924714708998653185922, f_q))
mstore(0xc20, mulmod(mload(0xb80), 6852144584591678924477440653887876563116097870276213106119596023961179534039, f_q))
mstore(0xc40, addmod(mload(0x4c0), 15036098287247596297768965091369398525432266530139821237578608162614628961578, f_q))
mstore(0xc60, mulmod(mload(0xb80), 6363119021782681274480715230122258277189830284152385293217720612674619714422, f_q))
mstore(0xc80, addmod(mload(0x4c0), 15525123850056593947765690515135016811358534116263649050480483573901188781195, f_q))
mstore(0xca0, mulmod(mload(0xb80), 495188420091111145957709789221178673495499187437761988132837836548330853701, f_q))
mstore(0xcc0, addmod(mload(0x4c0), 21393054451748164076288695956036096415052865212978272355565366350027477641916, f_q))
mstore(0xce0, mulmod(mload(0xb80), 14686510910986211321976396297238126901237973400949744736326777596334651355305, f_q))
mstore(0xd00, addmod(mload(0x4c0), 7201731960853063900270009448019148187310390999466289607371426590241157140312, f_q))
mstore(0xd20, mulmod(mload(0xb80), 15402826414547299628414612080036060696555554914079673875872749760617770134879, f_q))
mstore(0xd40, addmod(mload(0x4c0), 6485416457291975593831793665221214391992809486336360467825454425958038360738, f_q))
mstore(0xd60, mulmod(mload(0xb80), 1, f_q))
mstore(0xd80, addmod(mload(0x4c0), 21888242871839275222246405745257275088548364400416034343698204186575808495616, f_q))
{
            let prod := mload(0xbc0)

                prod := mulmod(mload(0xc00), prod, f_q)
                mstore(0xda0, prod)
            
                prod := mulmod(mload(0xc40), prod, f_q)
                mstore(0xdc0, prod)
            
                prod := mulmod(mload(0xc80), prod, f_q)
                mstore(0xde0, prod)
            
                prod := mulmod(mload(0xcc0), prod, f_q)
                mstore(0xe00, prod)
            
                prod := mulmod(mload(0xd00), prod, f_q)
                mstore(0xe20, prod)
            
                prod := mulmod(mload(0xd40), prod, f_q)
                mstore(0xe40, prod)
            
                prod := mulmod(mload(0xd80), prod, f_q)
                mstore(0xe60, prod)
            
                prod := mulmod(mload(0xb60), prod, f_q)
                mstore(0xe80, prod)
            
        }
mstore(0xec0, 32)
mstore(0xee0, 32)
mstore(0xf00, 32)
mstore(0xf20, mload(0xe80))
mstore(0xf40, 21888242871839275222246405745257275088548364400416034343698204186575808495615)
mstore(0xf60, 21888242871839275222246405745257275088548364400416034343698204186575808495617)
success := and(eq(staticcall(gas(), 0x5, 0xec0, 0xc0, 0xea0, 0x20), 1), success)
{
            
            let inv := mload(0xea0)
            let v
        
                    v := mload(0xb60)
                    mstore(2912, mulmod(mload(0xe60), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xd80)
                    mstore(3456, mulmod(mload(0xe40), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xd40)
                    mstore(3392, mulmod(mload(0xe20), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xd00)
                    mstore(3328, mulmod(mload(0xe00), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xcc0)
                    mstore(3264, mulmod(mload(0xde0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xc80)
                    mstore(3200, mulmod(mload(0xdc0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xc40)
                    mstore(3136, mulmod(mload(0xda0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xc00)
                    mstore(3072, mulmod(mload(0xbc0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                mstore(0xbc0, inv)

        }
mstore(0xf80, mulmod(mload(0xba0), mload(0xbc0), f_q))
mstore(0xfa0, mulmod(mload(0xbe0), mload(0xc00), f_q))
mstore(0xfc0, mulmod(mload(0xc20), mload(0xc40), f_q))
mstore(0xfe0, mulmod(mload(0xc60), mload(0xc80), f_q))
mstore(0x1000, mulmod(mload(0xca0), mload(0xcc0), f_q))
mstore(0x1020, mulmod(mload(0xce0), mload(0xd00), f_q))
mstore(0x1040, mulmod(mload(0xd20), mload(0xd40), f_q))
mstore(0x1060, mulmod(mload(0xd60), mload(0xd80), f_q))
mstore(0x1080, mulmod(mload(0x540), mload(0x520), f_q))
mstore(0x10a0, addmod(mload(0x500), mload(0x1080), f_q))
mstore(0x10c0, addmod(mload(0x10a0), sub(f_q, mload(0x560)), f_q))
mstore(0x10e0, mulmod(mload(0x10c0), mload(0x5c0), f_q))
mstore(0x1100, mulmod(mload(0x360), mload(0x10e0), f_q))
mstore(0x1120, addmod(1, sub(f_q, mload(0x660)), f_q))
mstore(0x1140, mulmod(mload(0x1120), mload(0x1060), f_q))
mstore(0x1160, addmod(mload(0x1100), mload(0x1140), f_q))
mstore(0x1180, mulmod(mload(0x360), mload(0x1160), f_q))
mstore(0x11a0, mulmod(mload(0x660), mload(0x660), f_q))
mstore(0x11c0, addmod(mload(0x11a0), sub(f_q, mload(0x660)), f_q))
mstore(0x11e0, mulmod(mload(0x11c0), mload(0xf80), f_q))
mstore(0x1200, addmod(mload(0x1180), mload(0x11e0), f_q))
mstore(0x1220, mulmod(mload(0x360), mload(0x1200), f_q))
mstore(0x1240, addmod(1, sub(f_q, mload(0xf80)), f_q))
mstore(0x1260, addmod(mload(0xfa0), mload(0xfc0), f_q))
mstore(0x1280, addmod(mload(0x1260), mload(0xfe0), f_q))
mstore(0x12a0, addmod(mload(0x1280), mload(0x1000), f_q))
mstore(0x12c0, addmod(mload(0x12a0), mload(0x1020), f_q))
mstore(0x12e0, addmod(mload(0x12c0), mload(0x1040), f_q))
mstore(0x1300, addmod(mload(0x1240), sub(f_q, mload(0x12e0)), f_q))
mstore(0x1320, mulmod(mload(0x620), mload(0x1e0), f_q))
mstore(0x1340, addmod(mload(0x580), mload(0x1320), f_q))
mstore(0x1360, addmod(mload(0x1340), mload(0x240), f_q))
mstore(0x1380, mulmod(mload(0x640), mload(0x1e0), f_q))
mstore(0x13a0, addmod(mload(0x500), mload(0x1380), f_q))
mstore(0x13c0, addmod(mload(0x13a0), mload(0x240), f_q))
mstore(0x13e0, mulmod(mload(0x13c0), mload(0x1360), f_q))
mstore(0x1400, mulmod(mload(0x13e0), mload(0x680), f_q))
mstore(0x1420, mulmod(1, mload(0x1e0), f_q))
mstore(0x1440, mulmod(mload(0x4c0), mload(0x1420), f_q))
mstore(0x1460, addmod(mload(0x580), mload(0x1440), f_q))
mstore(0x1480, addmod(mload(0x1460), mload(0x240), f_q))
mstore(0x14a0, mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, mload(0x1e0), f_q))
mstore(0x14c0, mulmod(mload(0x4c0), mload(0x14a0), f_q))
mstore(0x14e0, addmod(mload(0x500), mload(0x14c0), f_q))
mstore(0x1500, addmod(mload(0x14e0), mload(0x240), f_q))
mstore(0x1520, mulmod(mload(0x1500), mload(0x1480), f_q))
mstore(0x1540, mulmod(mload(0x1520), mload(0x660), f_q))
mstore(0x1560, addmod(mload(0x1400), sub(f_q, mload(0x1540)), f_q))
mstore(0x1580, mulmod(mload(0x1560), mload(0x1300), f_q))
mstore(0x15a0, addmod(mload(0x1220), mload(0x1580), f_q))
mstore(0x15c0, mulmod(mload(0x360), mload(0x15a0), f_q))
mstore(0x15e0, addmod(1, sub(f_q, mload(0x6a0)), f_q))
mstore(0x1600, mulmod(mload(0x15e0), mload(0x1060), f_q))
mstore(0x1620, addmod(mload(0x15c0), mload(0x1600), f_q))
mstore(0x1640, mulmod(mload(0x360), mload(0x1620), f_q))
mstore(0x1660, mulmod(mload(0x6a0), mload(0x6a0), f_q))
mstore(0x1680, addmod(mload(0x1660), sub(f_q, mload(0x6a0)), f_q))
mstore(0x16a0, mulmod(mload(0x1680), mload(0xf80), f_q))
mstore(0x16c0, addmod(mload(0x1640), mload(0x16a0), f_q))
mstore(0x16e0, mulmod(mload(0x360), mload(0x16c0), f_q))
mstore(0x1700, addmod(mload(0x6e0), mload(0x1e0), f_q))
mstore(0x1720, mulmod(mload(0x1700), mload(0x6c0), f_q))
mstore(0x1740, addmod(mload(0x720), mload(0x240), f_q))
mstore(0x1760, mulmod(mload(0x1740), mload(0x1720), f_q))
mstore(0x1780, mulmod(mload(0x500), mload(0x5e0), f_q))
mstore(0x17a0, addmod(mload(0x1780), mload(0x1e0), f_q))
mstore(0x17c0, mulmod(mload(0x17a0), mload(0x6a0), f_q))
mstore(0x17e0, addmod(mload(0x5a0), mload(0x240), f_q))
mstore(0x1800, mulmod(mload(0x17e0), mload(0x17c0), f_q))
mstore(0x1820, addmod(mload(0x1760), sub(f_q, mload(0x1800)), f_q))
mstore(0x1840, mulmod(mload(0x1820), mload(0x1300), f_q))
mstore(0x1860, addmod(mload(0x16e0), mload(0x1840), f_q))
mstore(0x1880, mulmod(mload(0x360), mload(0x1860), f_q))
mstore(0x18a0, addmod(mload(0x6e0), sub(f_q, mload(0x720)), f_q))
mstore(0x18c0, mulmod(mload(0x18a0), mload(0x1060), f_q))
mstore(0x18e0, addmod(mload(0x1880), mload(0x18c0), f_q))
mstore(0x1900, mulmod(mload(0x360), mload(0x18e0), f_q))
mstore(0x1920, mulmod(mload(0x18a0), mload(0x1300), f_q))
mstore(0x1940, addmod(mload(0x6e0), sub(f_q, mload(0x700)), f_q))
mstore(0x1960, mulmod(mload(0x1940), mload(0x1920), f_q))
mstore(0x1980, addmod(mload(0x1900), mload(0x1960), f_q))
mstore(0x19a0, mulmod(mload(0xb40), mload(0xb40), f_q))
mstore(0x19c0, mulmod(mload(0x19a0), mload(0xb40), f_q))
mstore(0x19e0, mulmod(mload(0x19c0), mload(0xb40), f_q))
mstore(0x1a00, mulmod(1, mload(0xb40), f_q))
mstore(0x1a20, mulmod(1, mload(0x19a0), f_q))
mstore(0x1a40, mulmod(1, mload(0x19c0), f_q))
mstore(0x1a60, mulmod(mload(0x1980), mload(0xb60), f_q))
mstore(0x1a80, mulmod(mload(0x8e0), mload(0x4c0), f_q))
mstore(0x1aa0, mulmod(mload(0x1a80), mload(0x4c0), f_q))
mstore(0x1ac0, mulmod(mload(0x4c0), 15402826414547299628414612080036060696555554914079673875872749760617770134879, f_q))
mstore(0x1ae0, addmod(mload(0x860), sub(f_q, mload(0x1ac0)), f_q))
mstore(0x1b00, mulmod(mload(0x4c0), 1, f_q))
mstore(0x1b20, addmod(mload(0x860), sub(f_q, mload(0x1b00)), f_q))
mstore(0x1b40, mulmod(mload(0x4c0), 19032961837237948602743626455740240236231119053033140765040043513661803148152, f_q))
mstore(0x1b60, addmod(mload(0x860), sub(f_q, mload(0x1b40)), f_q))
mstore(0x1b80, mulmod(mload(0x4c0), 5854133144571823792863860130267644613802765696134002830362054821530146160770, f_q))
mstore(0x1ba0, addmod(mload(0x860), sub(f_q, mload(0x1b80)), f_q))
mstore(0x1bc0, mulmod(mload(0x4c0), 9697063347556872083384215826199993067635178715531258559890418744774301211662, f_q))
mstore(0x1be0, addmod(mload(0x860), sub(f_q, mload(0x1bc0)), f_q))
mstore(0x1c00, mulmod(4736883668178346996545086986819627905372801785859861761039164455939474815882, mload(0x1a80), f_q))
mstore(0x1c20, mulmod(mload(0x1c00), 1, f_q))
{
            let result := mulmod(mload(0x860), mload(0x1c00), f_q)
result := addmod(mulmod(mload(0x4c0), sub(f_q, mload(0x1c20)), f_q), result, f_q)
mstore(7232, result)
        }
mstore(0x1c60, mulmod(7470511806983226874498209297862392041888689988572294883423852458120126520044, mload(0x1a80), f_q))
mstore(0x1c80, mulmod(mload(0x1c60), 19032961837237948602743626455740240236231119053033140765040043513661803148152, f_q))
{
            let result := mulmod(mload(0x860), mload(0x1c60), f_q)
result := addmod(mulmod(mload(0x4c0), sub(f_q, mload(0x1c80)), f_q), result, f_q)
mstore(7328, result)
        }
mstore(0x1cc0, mulmod(2224530251973873386125196487739371278694624537245101772475500710314493913191, mload(0x1a80), f_q))
mstore(0x1ce0, mulmod(mload(0x1cc0), 5854133144571823792863860130267644613802765696134002830362054821530146160770, f_q))
{
            let result := mulmod(mload(0x860), mload(0x1cc0), f_q)
result := addmod(mulmod(mload(0x4c0), sub(f_q, mload(0x1ce0)), f_q), result, f_q)
mstore(7424, result)
        }
mstore(0x1d20, mulmod(1469155162432328970349083792793126972705202636972386811938550155728152863999, mload(0x1a80), f_q))
mstore(0x1d40, mulmod(mload(0x1d20), 9697063347556872083384215826199993067635178715531258559890418744774301211662, f_q))
{
            let result := mulmod(mload(0x860), mload(0x1d20), f_q)
result := addmod(mulmod(mload(0x4c0), sub(f_q, mload(0x1d40)), f_q), result, f_q)
mstore(7520, result)
        }
mstore(0x1d80, mulmod(1, mload(0x1b20), f_q))
mstore(0x1da0, mulmod(mload(0x1d80), mload(0x1b60), f_q))
mstore(0x1dc0, mulmod(mload(0x1da0), mload(0x1ba0), f_q))
mstore(0x1de0, mulmod(mload(0x1dc0), mload(0x1be0), f_q))
mstore(0x1e00, mulmod(2855281034601326619502779289517034852317245347382893578658160672914005347466, mload(0x4c0), f_q))
mstore(0x1e20, mulmod(mload(0x1e00), 1, f_q))
{
            let result := mulmod(mload(0x860), mload(0x1e00), f_q)
result := addmod(mulmod(mload(0x4c0), sub(f_q, mload(0x1e20)), f_q), result, f_q)
mstore(7744, result)
        }
mstore(0x1e60, mulmod(19032961837237948602743626455740240236231119053033140765040043513661803148151, mload(0x4c0), f_q))
mstore(0x1e80, mulmod(mload(0x1e60), 19032961837237948602743626455740240236231119053033140765040043513661803148152, f_q))
{
            let result := mulmod(mload(0x860), mload(0x1e60), f_q)
result := addmod(mulmod(mload(0x4c0), sub(f_q, mload(0x1e80)), f_q), result, f_q)
mstore(7840, result)
        }
mstore(0x1ec0, mulmod(6485416457291975593831793665221214391992809486336360467825454425958038360739, mload(0x4c0), f_q))
mstore(0x1ee0, mulmod(mload(0x1ec0), 1, f_q))
{
            let result := mulmod(mload(0x860), mload(0x1ec0), f_q)
result := addmod(mulmod(mload(0x4c0), sub(f_q, mload(0x1ee0)), f_q), result, f_q)
mstore(7936, result)
        }
mstore(0x1f20, mulmod(15402826414547299628414612080036060696555554914079673875872749760617770134878, mload(0x4c0), f_q))
mstore(0x1f40, mulmod(mload(0x1f20), 15402826414547299628414612080036060696555554914079673875872749760617770134879, f_q))
{
            let result := mulmod(mload(0x860), mload(0x1f20), f_q)
result := addmod(mulmod(mload(0x4c0), sub(f_q, mload(0x1f40)), f_q), result, f_q)
mstore(8032, result)
        }
mstore(0x1f80, mulmod(mload(0x1d80), mload(0x1ae0), f_q))
{
            let result := mulmod(mload(0x860), 1, f_q)
result := addmod(mulmod(mload(0x4c0), 21888242871839275222246405745257275088548364400416034343698204186575808495616, f_q), result, f_q)
mstore(8096, result)
        }
{
            let prod := mload(0x1c40)

                prod := mulmod(mload(0x1ca0), prod, f_q)
                mstore(0x1fc0, prod)
            
                prod := mulmod(mload(0x1d00), prod, f_q)
                mstore(0x1fe0, prod)
            
                prod := mulmod(mload(0x1d60), prod, f_q)
                mstore(0x2000, prod)
            
                prod := mulmod(mload(0x1e40), prod, f_q)
                mstore(0x2020, prod)
            
                prod := mulmod(mload(0x1ea0), prod, f_q)
                mstore(0x2040, prod)
            
                prod := mulmod(mload(0x1da0), prod, f_q)
                mstore(0x2060, prod)
            
                prod := mulmod(mload(0x1f00), prod, f_q)
                mstore(0x2080, prod)
            
                prod := mulmod(mload(0x1f60), prod, f_q)
                mstore(0x20a0, prod)
            
                prod := mulmod(mload(0x1f80), prod, f_q)
                mstore(0x20c0, prod)
            
                prod := mulmod(mload(0x1fa0), prod, f_q)
                mstore(0x20e0, prod)
            
                prod := mulmod(mload(0x1d80), prod, f_q)
                mstore(0x2100, prod)
            
        }
mstore(0x2140, 32)
mstore(0x2160, 32)
mstore(0x2180, 32)
mstore(0x21a0, mload(0x2100))
mstore(0x21c0, 21888242871839275222246405745257275088548364400416034343698204186575808495615)
mstore(0x21e0, 21888242871839275222246405745257275088548364400416034343698204186575808495617)
success := and(eq(staticcall(gas(), 0x5, 0x2140, 0xc0, 0x2120, 0x20), 1), success)
{
            
            let inv := mload(0x2120)
            let v
        
                    v := mload(0x1d80)
                    mstore(7552, mulmod(mload(0x20e0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x1fa0)
                    mstore(8096, mulmod(mload(0x20c0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x1f80)
                    mstore(8064, mulmod(mload(0x20a0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x1f60)
                    mstore(8032, mulmod(mload(0x2080), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x1f00)
                    mstore(7936, mulmod(mload(0x2060), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x1da0)
                    mstore(7584, mulmod(mload(0x2040), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x1ea0)
                    mstore(7840, mulmod(mload(0x2020), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x1e40)
                    mstore(7744, mulmod(mload(0x2000), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x1d60)
                    mstore(7520, mulmod(mload(0x1fe0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x1d00)
                    mstore(7424, mulmod(mload(0x1fc0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x1ca0)
                    mstore(7328, mulmod(mload(0x1c40), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                mstore(0x1c40, inv)

        }
{
            let result := mload(0x1c40)
result := addmod(mload(0x1ca0), result, f_q)
result := addmod(mload(0x1d00), result, f_q)
result := addmod(mload(0x1d60), result, f_q)
mstore(8704, result)
        }
mstore(0x2220, mulmod(mload(0x1de0), mload(0x1da0), f_q))
{
            let result := mload(0x1e40)
result := addmod(mload(0x1ea0), result, f_q)
mstore(8768, result)
        }
mstore(0x2260, mulmod(mload(0x1de0), mload(0x1f80), f_q))
{
            let result := mload(0x1f00)
result := addmod(mload(0x1f60), result, f_q)
mstore(8832, result)
        }
mstore(0x22a0, mulmod(mload(0x1de0), mload(0x1d80), f_q))
{
            let result := mload(0x1fa0)
mstore(8896, result)
        }
{
            let prod := mload(0x2200)

                prod := mulmod(mload(0x2240), prod, f_q)
                mstore(0x22e0, prod)
            
                prod := mulmod(mload(0x2280), prod, f_q)
                mstore(0x2300, prod)
            
                prod := mulmod(mload(0x22c0), prod, f_q)
                mstore(0x2320, prod)
            
        }
mstore(0x2360, 32)
mstore(0x2380, 32)
mstore(0x23a0, 32)
mstore(0x23c0, mload(0x2320))
mstore(0x23e0, 21888242871839275222246405745257275088548364400416034343698204186575808495615)
mstore(0x2400, 21888242871839275222246405745257275088548364400416034343698204186575808495617)
success := and(eq(staticcall(gas(), 0x5, 0x2360, 0xc0, 0x2340, 0x20), 1), success)
{
            
            let inv := mload(0x2340)
            let v
        
                    v := mload(0x22c0)
                    mstore(8896, mulmod(mload(0x2300), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2280)
                    mstore(8832, mulmod(mload(0x22e0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2240)
                    mstore(8768, mulmod(mload(0x2200), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                mstore(0x2200, inv)

        }
mstore(0x2420, mulmod(mload(0x2220), mload(0x2240), f_q))
mstore(0x2440, mulmod(mload(0x2260), mload(0x2280), f_q))
mstore(0x2460, mulmod(mload(0x22a0), mload(0x22c0), f_q))
mstore(0x2480, mulmod(mload(0x760), mload(0x760), f_q))
mstore(0x24a0, mulmod(mload(0x2480), mload(0x760), f_q))
mstore(0x24c0, mulmod(mload(0x24a0), mload(0x760), f_q))
mstore(0x24e0, mulmod(mload(0x24c0), mload(0x760), f_q))
mstore(0x2500, mulmod(mload(0x24e0), mload(0x760), f_q))
mstore(0x2520, mulmod(mload(0x2500), mload(0x760), f_q))
mstore(0x2540, mulmod(mload(0x2520), mload(0x760), f_q))
mstore(0x2560, mulmod(mload(0x2540), mload(0x760), f_q))
mstore(0x2580, mulmod(mload(0x7c0), mload(0x7c0), f_q))
mstore(0x25a0, mulmod(mload(0x2580), mload(0x7c0), f_q))
mstore(0x25c0, mulmod(mload(0x25a0), mload(0x7c0), f_q))
{
            let result := mulmod(mload(0x500), mload(0x1c40), f_q)
result := addmod(mulmod(mload(0x520), mload(0x1ca0), f_q), result, f_q)
result := addmod(mulmod(mload(0x540), mload(0x1d00), f_q), result, f_q)
result := addmod(mulmod(mload(0x560), mload(0x1d60), f_q), result, f_q)
mstore(9696, result)
        }
mstore(0x2600, mulmod(mload(0x25e0), mload(0x2200), f_q))
mstore(0x2620, mulmod(sub(f_q, mload(0x2600)), 1, f_q))
mstore(0x2640, mulmod(mload(0x2620), 1, f_q))
mstore(0x2660, mulmod(1, mload(0x2220), f_q))
{
            let result := mulmod(mload(0x660), mload(0x1e40), f_q)
result := addmod(mulmod(mload(0x680), mload(0x1ea0), f_q), result, f_q)
mstore(9856, result)
        }
mstore(0x26a0, mulmod(mload(0x2680), mload(0x2420), f_q))
mstore(0x26c0, mulmod(sub(f_q, mload(0x26a0)), 1, f_q))
mstore(0x26e0, mulmod(mload(0x2660), 1, f_q))
{
            let result := mulmod(mload(0x6a0), mload(0x1e40), f_q)
result := addmod(mulmod(mload(0x6c0), mload(0x1ea0), f_q), result, f_q)
mstore(9984, result)
        }
mstore(0x2720, mulmod(mload(0x2700), mload(0x2420), f_q))
mstore(0x2740, mulmod(sub(f_q, mload(0x2720)), mload(0x760), f_q))
mstore(0x2760, mulmod(mload(0x2660), mload(0x760), f_q))
mstore(0x2780, addmod(mload(0x26c0), mload(0x2740), f_q))
mstore(0x27a0, mulmod(mload(0x2780), mload(0x7c0), f_q))
mstore(0x27c0, mulmod(mload(0x26e0), mload(0x7c0), f_q))
mstore(0x27e0, mulmod(mload(0x2760), mload(0x7c0), f_q))
mstore(0x2800, addmod(mload(0x2640), mload(0x27a0), f_q))
mstore(0x2820, mulmod(1, mload(0x2260), f_q))
{
            let result := mulmod(mload(0x6e0), mload(0x1f00), f_q)
result := addmod(mulmod(mload(0x700), mload(0x1f60), f_q), result, f_q)
mstore(10304, result)
        }
mstore(0x2860, mulmod(mload(0x2840), mload(0x2440), f_q))
mstore(0x2880, mulmod(sub(f_q, mload(0x2860)), 1, f_q))
mstore(0x28a0, mulmod(mload(0x2820), 1, f_q))
mstore(0x28c0, mulmod(mload(0x2880), mload(0x2580), f_q))
mstore(0x28e0, mulmod(mload(0x28a0), mload(0x2580), f_q))
mstore(0x2900, addmod(mload(0x2800), mload(0x28c0), f_q))
mstore(0x2920, mulmod(1, mload(0x22a0), f_q))
{
            let result := mulmod(mload(0x720), mload(0x1fa0), f_q)
mstore(10560, result)
        }
mstore(0x2960, mulmod(mload(0x2940), mload(0x2460), f_q))
mstore(0x2980, mulmod(sub(f_q, mload(0x2960)), 1, f_q))
mstore(0x29a0, mulmod(mload(0x2920), 1, f_q))
{
            let result := mulmod(mload(0x580), mload(0x1fa0), f_q)
mstore(10688, result)
        }
mstore(0x29e0, mulmod(mload(0x29c0), mload(0x2460), f_q))
mstore(0x2a00, mulmod(sub(f_q, mload(0x29e0)), mload(0x760), f_q))
mstore(0x2a20, mulmod(mload(0x2920), mload(0x760), f_q))
mstore(0x2a40, addmod(mload(0x2980), mload(0x2a00), f_q))
{
            let result := mulmod(mload(0x5a0), mload(0x1fa0), f_q)
mstore(10848, result)
        }
mstore(0x2a80, mulmod(mload(0x2a60), mload(0x2460), f_q))
mstore(0x2aa0, mulmod(sub(f_q, mload(0x2a80)), mload(0x2480), f_q))
mstore(0x2ac0, mulmod(mload(0x2920), mload(0x2480), f_q))
mstore(0x2ae0, addmod(mload(0x2a40), mload(0x2aa0), f_q))
{
            let result := mulmod(mload(0x5c0), mload(0x1fa0), f_q)
mstore(11008, result)
        }
mstore(0x2b20, mulmod(mload(0x2b00), mload(0x2460), f_q))
mstore(0x2b40, mulmod(sub(f_q, mload(0x2b20)), mload(0x24a0), f_q))
mstore(0x2b60, mulmod(mload(0x2920), mload(0x24a0), f_q))
mstore(0x2b80, addmod(mload(0x2ae0), mload(0x2b40), f_q))
{
            let result := mulmod(mload(0x5e0), mload(0x1fa0), f_q)
mstore(11168, result)
        }
mstore(0x2bc0, mulmod(mload(0x2ba0), mload(0x2460), f_q))
mstore(0x2be0, mulmod(sub(f_q, mload(0x2bc0)), mload(0x24c0), f_q))
mstore(0x2c00, mulmod(mload(0x2920), mload(0x24c0), f_q))
mstore(0x2c20, addmod(mload(0x2b80), mload(0x2be0), f_q))
{
            let result := mulmod(mload(0x620), mload(0x1fa0), f_q)
mstore(11328, result)
        }
mstore(0x2c60, mulmod(mload(0x2c40), mload(0x2460), f_q))
mstore(0x2c80, mulmod(sub(f_q, mload(0x2c60)), mload(0x24e0), f_q))
mstore(0x2ca0, mulmod(mload(0x2920), mload(0x24e0), f_q))
mstore(0x2cc0, addmod(mload(0x2c20), mload(0x2c80), f_q))
{
            let result := mulmod(mload(0x640), mload(0x1fa0), f_q)
mstore(11488, result)
        }
mstore(0x2d00, mulmod(mload(0x2ce0), mload(0x2460), f_q))
mstore(0x2d20, mulmod(sub(f_q, mload(0x2d00)), mload(0x2500), f_q))
mstore(0x2d40, mulmod(mload(0x2920), mload(0x2500), f_q))
mstore(0x2d60, addmod(mload(0x2cc0), mload(0x2d20), f_q))
mstore(0x2d80, mulmod(mload(0x1a00), mload(0x22a0), f_q))
mstore(0x2da0, mulmod(mload(0x1a20), mload(0x22a0), f_q))
mstore(0x2dc0, mulmod(mload(0x1a40), mload(0x22a0), f_q))
{
            let result := mulmod(mload(0x1a60), mload(0x1fa0), f_q)
mstore(11744, result)
        }
mstore(0x2e00, mulmod(mload(0x2de0), mload(0x2460), f_q))
mstore(0x2e20, mulmod(sub(f_q, mload(0x2e00)), mload(0x2520), f_q))
mstore(0x2e40, mulmod(mload(0x2920), mload(0x2520), f_q))
mstore(0x2e60, mulmod(mload(0x2d80), mload(0x2520), f_q))
mstore(0x2e80, mulmod(mload(0x2da0), mload(0x2520), f_q))
mstore(0x2ea0, mulmod(mload(0x2dc0), mload(0x2520), f_q))
mstore(0x2ec0, addmod(mload(0x2d60), mload(0x2e20), f_q))
{
            let result := mulmod(mload(0x600), mload(0x1fa0), f_q)
mstore(12000, result)
        }
mstore(0x2f00, mulmod(mload(0x2ee0), mload(0x2460), f_q))
mstore(0x2f20, mulmod(sub(f_q, mload(0x2f00)), mload(0x2540), f_q))
mstore(0x2f40, mulmod(mload(0x2920), mload(0x2540), f_q))
mstore(0x2f60, addmod(mload(0x2ec0), mload(0x2f20), f_q))
mstore(0x2f80, mulmod(mload(0x2f60), mload(0x25a0), f_q))
mstore(0x2fa0, mulmod(mload(0x29a0), mload(0x25a0), f_q))
mstore(0x2fc0, mulmod(mload(0x2a20), mload(0x25a0), f_q))
mstore(0x2fe0, mulmod(mload(0x2ac0), mload(0x25a0), f_q))
mstore(0x3000, mulmod(mload(0x2b60), mload(0x25a0), f_q))
mstore(0x3020, mulmod(mload(0x2c00), mload(0x25a0), f_q))
mstore(0x3040, mulmod(mload(0x2ca0), mload(0x25a0), f_q))
mstore(0x3060, mulmod(mload(0x2d40), mload(0x25a0), f_q))
mstore(0x3080, mulmod(mload(0x2e40), mload(0x25a0), f_q))
mstore(0x30a0, mulmod(mload(0x2e60), mload(0x25a0), f_q))
mstore(0x30c0, mulmod(mload(0x2e80), mload(0x25a0), f_q))
mstore(0x30e0, mulmod(mload(0x2ea0), mload(0x25a0), f_q))
mstore(0x3100, mulmod(mload(0x2f40), mload(0x25a0), f_q))
mstore(0x3120, addmod(mload(0x2900), mload(0x2f80), f_q))
mstore(0x3140, mulmod(1, mload(0x1de0), f_q))
mstore(0x3160, mulmod(1, mload(0x860), f_q))
mstore(0x3180, 0x0000000000000000000000000000000000000000000000000000000000000001)
                    mstore(0x31a0, 0x0000000000000000000000000000000000000000000000000000000000000002)
mstore(0x31c0, mload(0x3120))
success := and(eq(staticcall(gas(), 0x7, 0x3180, 0x60, 0x3180, 0x40), 1), success)
mstore(0x31e0, mload(0x3180))
                    mstore(0x3200, mload(0x31a0))
mstore(0x3220, mload(0xa0))
                    mstore(0x3240, mload(0xc0))
success := and(eq(staticcall(gas(), 0x6, 0x31e0, 0x80, 0x31e0, 0x40), 1), success)
mstore(0x3260, mload(0x280))
                    mstore(0x3280, mload(0x2a0))
mstore(0x32a0, mload(0x27c0))
success := and(eq(staticcall(gas(), 0x7, 0x3260, 0x60, 0x3260, 0x40), 1), success)
mstore(0x32c0, mload(0x31e0))
                    mstore(0x32e0, mload(0x3200))
mstore(0x3300, mload(0x3260))
                    mstore(0x3320, mload(0x3280))
success := and(eq(staticcall(gas(), 0x6, 0x32c0, 0x80, 0x32c0, 0x40), 1), success)
mstore(0x3340, mload(0x2c0))
                    mstore(0x3360, mload(0x2e0))
mstore(0x3380, mload(0x27e0))
success := and(eq(staticcall(gas(), 0x7, 0x3340, 0x60, 0x3340, 0x40), 1), success)
mstore(0x33a0, mload(0x32c0))
                    mstore(0x33c0, mload(0x32e0))
mstore(0x33e0, mload(0x3340))
                    mstore(0x3400, mload(0x3360))
success := and(eq(staticcall(gas(), 0x6, 0x33a0, 0x80, 0x33a0, 0x40), 1), success)
mstore(0x3420, mload(0x140))
                    mstore(0x3440, mload(0x160))
mstore(0x3460, mload(0x28e0))
success := and(eq(staticcall(gas(), 0x7, 0x3420, 0x60, 0x3420, 0x40), 1), success)
mstore(0x3480, mload(0x33a0))
                    mstore(0x34a0, mload(0x33c0))
mstore(0x34c0, mload(0x3420))
                    mstore(0x34e0, mload(0x3440))
success := and(eq(staticcall(gas(), 0x6, 0x3480, 0x80, 0x3480, 0x40), 1), success)
mstore(0x3500, mload(0x180))
                    mstore(0x3520, mload(0x1a0))
mstore(0x3540, mload(0x2fa0))
success := and(eq(staticcall(gas(), 0x7, 0x3500, 0x60, 0x3500, 0x40), 1), success)
mstore(0x3560, mload(0x3480))
                    mstore(0x3580, mload(0x34a0))
mstore(0x35a0, mload(0x3500))
                    mstore(0x35c0, mload(0x3520))
success := and(eq(staticcall(gas(), 0x6, 0x3560, 0x80, 0x3560, 0x40), 1), success)
mstore(0x35e0, 0x08495aa297db2678f684841e1198be792946462a7ff39198d08393c805e24a67)
                    mstore(0x3600, 0x27def59876334e8c74db82718e75a8153653fe5469ea7a740a1bd8dfd3ff9695)
mstore(0x3620, mload(0x2fc0))
success := and(eq(staticcall(gas(), 0x7, 0x35e0, 0x60, 0x35e0, 0x40), 1), success)
mstore(0x3640, mload(0x3560))
                    mstore(0x3660, mload(0x3580))
mstore(0x3680, mload(0x35e0))
                    mstore(0x36a0, mload(0x3600))
success := and(eq(staticcall(gas(), 0x6, 0x3640, 0x80, 0x3640, 0x40), 1), success)
mstore(0x36c0, 0x2ee9dd5595355686622ab1968c8002576ae45b77bcf663995bf038d1f431818e)
                    mstore(0x36e0, 0x0ba65d473bed4602d51a303767f8c84d31ea956b5d812f3d52f07872960458a6)
mstore(0x3700, mload(0x2fe0))
success := and(eq(staticcall(gas(), 0x7, 0x36c0, 0x60, 0x36c0, 0x40), 1), success)
mstore(0x3720, mload(0x3640))
                    mstore(0x3740, mload(0x3660))
mstore(0x3760, mload(0x36c0))
                    mstore(0x3780, mload(0x36e0))
success := and(eq(staticcall(gas(), 0x6, 0x3720, 0x80, 0x3720, 0x40), 1), success)
mstore(0x37a0, 0x25581c6a112156f10099ef6e37a808f54dbf7d92b35b49f034b07ffb6e57104e)
                    mstore(0x37c0, 0x085b1dbb6f5437b46b35f61aa7f0ee4f8fc606dba2652e8b16a96f5632c42245)
mstore(0x37e0, mload(0x3000))
success := and(eq(staticcall(gas(), 0x7, 0x37a0, 0x60, 0x37a0, 0x40), 1), success)
mstore(0x3800, mload(0x3720))
                    mstore(0x3820, mload(0x3740))
mstore(0x3840, mload(0x37a0))
                    mstore(0x3860, mload(0x37c0))
success := and(eq(staticcall(gas(), 0x6, 0x3800, 0x80, 0x3800, 0x40), 1), success)
mstore(0x3880, 0x0cedbd698b56e73bd5f6a23be6a5cbc13b1953240d0b25e3b3a4044e3efade29)
                    mstore(0x38a0, 0x10f917c4766b1549ce6f608fbc2f83e522210d9df6b4dcd16ebeb6552c7f4903)
mstore(0x38c0, mload(0x3020))
success := and(eq(staticcall(gas(), 0x7, 0x3880, 0x60, 0x3880, 0x40), 1), success)
mstore(0x38e0, mload(0x3800))
                    mstore(0x3900, mload(0x3820))
mstore(0x3920, mload(0x3880))
                    mstore(0x3940, mload(0x38a0))
success := and(eq(staticcall(gas(), 0x6, 0x38e0, 0x80, 0x38e0, 0x40), 1), success)
mstore(0x3960, 0x102d2d9cc135e55842fb80d15aa4a67740d4e2c475cf2f967d2842737ac6c9b8)
                    mstore(0x3980, 0x21bb88346c4d6e69ef72d13333015a52f98768ef6f441aa2fb822538c04b2cb2)
mstore(0x39a0, mload(0x3040))
success := and(eq(staticcall(gas(), 0x7, 0x3960, 0x60, 0x3960, 0x40), 1), success)
mstore(0x39c0, mload(0x38e0))
                    mstore(0x39e0, mload(0x3900))
mstore(0x3a00, mload(0x3960))
                    mstore(0x3a20, mload(0x3980))
success := and(eq(staticcall(gas(), 0x6, 0x39c0, 0x80, 0x39c0, 0x40), 1), success)
mstore(0x3a40, 0x2b0fdeaaf7ac4abb72df58a151e1636fea714341e344641f0ed3d8dc3e30e4b2)
                    mstore(0x3a60, 0x2b4195263483bb9857ee75e6e47b33275d00a48298fa4ffa8fd4418f5ef3969c)
mstore(0x3a80, mload(0x3060))
success := and(eq(staticcall(gas(), 0x7, 0x3a40, 0x60, 0x3a40, 0x40), 1), success)
mstore(0x3aa0, mload(0x39c0))
                    mstore(0x3ac0, mload(0x39e0))
mstore(0x3ae0, mload(0x3a40))
                    mstore(0x3b00, mload(0x3a60))
success := and(eq(staticcall(gas(), 0x6, 0x3aa0, 0x80, 0x3aa0, 0x40), 1), success)
mstore(0x3b20, mload(0x3a0))
                    mstore(0x3b40, mload(0x3c0))
mstore(0x3b60, mload(0x3080))
success := and(eq(staticcall(gas(), 0x7, 0x3b20, 0x60, 0x3b20, 0x40), 1), success)
mstore(0x3b80, mload(0x3aa0))
                    mstore(0x3ba0, mload(0x3ac0))
mstore(0x3bc0, mload(0x3b20))
                    mstore(0x3be0, mload(0x3b40))
success := and(eq(staticcall(gas(), 0x6, 0x3b80, 0x80, 0x3b80, 0x40), 1), success)
mstore(0x3c00, mload(0x3e0))
                    mstore(0x3c20, mload(0x400))
mstore(0x3c40, mload(0x30a0))
success := and(eq(staticcall(gas(), 0x7, 0x3c00, 0x60, 0x3c00, 0x40), 1), success)
mstore(0x3c60, mload(0x3b80))
                    mstore(0x3c80, mload(0x3ba0))
mstore(0x3ca0, mload(0x3c00))
                    mstore(0x3cc0, mload(0x3c20))
success := and(eq(staticcall(gas(), 0x6, 0x3c60, 0x80, 0x3c60, 0x40), 1), success)
mstore(0x3ce0, mload(0x420))
                    mstore(0x3d00, mload(0x440))
mstore(0x3d20, mload(0x30c0))
success := and(eq(staticcall(gas(), 0x7, 0x3ce0, 0x60, 0x3ce0, 0x40), 1), success)
mstore(0x3d40, mload(0x3c60))
                    mstore(0x3d60, mload(0x3c80))
mstore(0x3d80, mload(0x3ce0))
                    mstore(0x3da0, mload(0x3d00))
success := and(eq(staticcall(gas(), 0x6, 0x3d40, 0x80, 0x3d40, 0x40), 1), success)
mstore(0x3dc0, mload(0x460))
                    mstore(0x3de0, mload(0x480))
mstore(0x3e00, mload(0x30e0))
success := and(eq(staticcall(gas(), 0x7, 0x3dc0, 0x60, 0x3dc0, 0x40), 1), success)
mstore(0x3e20, mload(0x3d40))
                    mstore(0x3e40, mload(0x3d60))
mstore(0x3e60, mload(0x3dc0))
                    mstore(0x3e80, mload(0x3de0))
success := and(eq(staticcall(gas(), 0x6, 0x3e20, 0x80, 0x3e20, 0x40), 1), success)
mstore(0x3ea0, mload(0x300))
                    mstore(0x3ec0, mload(0x320))
mstore(0x3ee0, mload(0x3100))
success := and(eq(staticcall(gas(), 0x7, 0x3ea0, 0x60, 0x3ea0, 0x40), 1), success)
mstore(0x3f00, mload(0x3e20))
                    mstore(0x3f20, mload(0x3e40))
mstore(0x3f40, mload(0x3ea0))
                    mstore(0x3f60, mload(0x3ec0))
success := and(eq(staticcall(gas(), 0x6, 0x3f00, 0x80, 0x3f00, 0x40), 1), success)
mstore(0x3f80, mload(0x800))
                    mstore(0x3fa0, mload(0x820))
mstore(0x3fc0, sub(f_q, mload(0x3140)))
success := and(eq(staticcall(gas(), 0x7, 0x3f80, 0x60, 0x3f80, 0x40), 1), success)
mstore(0x3fe0, mload(0x3f00))
                    mstore(0x4000, mload(0x3f20))
mstore(0x4020, mload(0x3f80))
                    mstore(0x4040, mload(0x3fa0))
success := and(eq(staticcall(gas(), 0x6, 0x3fe0, 0x80, 0x3fe0, 0x40), 1), success)
mstore(0x4060, mload(0x8a0))
                    mstore(0x4080, mload(0x8c0))
mstore(0x40a0, mload(0x3160))
success := and(eq(staticcall(gas(), 0x7, 0x4060, 0x60, 0x4060, 0x40), 1), success)
mstore(0x40c0, mload(0x3fe0))
                    mstore(0x40e0, mload(0x4000))
mstore(0x4100, mload(0x4060))
                    mstore(0x4120, mload(0x4080))
success := and(eq(staticcall(gas(), 0x6, 0x40c0, 0x80, 0x40c0, 0x40), 1), success)
mstore(0x4140, mload(0x40c0))
                    mstore(0x4160, mload(0x40e0))
mstore(0x4180, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2)
            mstore(0x41a0, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed)
            mstore(0x41c0, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b)
            mstore(0x41e0, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa)
mstore(0x4200, mload(0x8a0))
                    mstore(0x4220, mload(0x8c0))
mstore(0x4240, 0x0323bfd9a7a93cb6210a744c3c16e60da5f905bb5bb02b13cfcaca0a6c955693)
            mstore(0x4260, 0x25017ce732669ee1a7583361d33a6195ca97737ab426485a044f3e4549dcd7e4)
            mstore(0x4280, 0x09e0977a978cd2fc5933e9c7e3852259211a4575e19cf9dbcbf72605cc70ff97)
            mstore(0x42a0, 0x2b955e5a77477db3e369e004cedec470cf89dda232ec2549dbe47738b2e894b8)
success := and(eq(staticcall(gas(), 0x8, 0x4140, 0x180, 0x4140, 0x20), 1), success)
success := and(eq(mload(0x4140), 1), success)

            // Revert if anything fails
            if iszero(success) { revert(0, 0) }

            // Return empty bytes on success
            return(0, 0)

        }
    }
}
        