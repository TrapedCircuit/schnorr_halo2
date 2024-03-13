
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
            mstore(0x80, 1426016272523260415980601283319139987605986270680862241854945995563425352919)

        {
            let x := calldataload(0x0)
            mstore(0xa0, x)
            let y := calldataload(0x20)
            mstore(0xc0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x40)
            mstore(0xe0, x)
            let y := calldataload(0x60)
            mstore(0x100, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x80)
            mstore(0x120, x)
            let y := calldataload(0xa0)
            mstore(0x140, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0x160, keccak256(0x80, 224))
{
            let hash := mload(0x160)
            mstore(0x180, mod(hash, f_q))
            mstore(0x1a0, hash)
        }

        {
            let x := calldataload(0xc0)
            mstore(0x1c0, x)
            let y := calldataload(0xe0)
            mstore(0x1e0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x100)
            mstore(0x200, x)
            let y := calldataload(0x120)
            mstore(0x220, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0x240, keccak256(0x1a0, 160))
{
            let hash := mload(0x240)
            mstore(0x260, mod(hash, f_q))
            mstore(0x280, hash)
        }
mstore8(672, 1)
mstore(0x2a0, keccak256(0x280, 33))
{
            let hash := mload(0x2a0)
            mstore(0x2c0, mod(hash, f_q))
            mstore(0x2e0, hash)
        }

        {
            let x := calldataload(0x140)
            mstore(0x300, x)
            let y := calldataload(0x160)
            mstore(0x320, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x180)
            mstore(0x340, x)
            let y := calldataload(0x1a0)
            mstore(0x360, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x1c0)
            mstore(0x380, x)
            let y := calldataload(0x1e0)
            mstore(0x3a0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x200)
            mstore(0x3c0, x)
            let y := calldataload(0x220)
            mstore(0x3e0, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0x400, keccak256(0x2e0, 288))
{
            let hash := mload(0x400)
            mstore(0x420, mod(hash, f_q))
            mstore(0x440, hash)
        }

        {
            let x := calldataload(0x240)
            mstore(0x460, x)
            let y := calldataload(0x260)
            mstore(0x480, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x280)
            mstore(0x4a0, x)
            let y := calldataload(0x2a0)
            mstore(0x4c0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x2c0)
            mstore(0x4e0, x)
            let y := calldataload(0x2e0)
            mstore(0x500, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0x520, keccak256(0x440, 224))
{
            let hash := mload(0x520)
            mstore(0x540, mod(hash, f_q))
            mstore(0x560, hash)
        }
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
mstore(0x740, mod(calldataload(0x4c0), f_q))
mstore(0x760, mod(calldataload(0x4e0), f_q))
mstore(0x780, mod(calldataload(0x500), f_q))
mstore(0x7a0, mod(calldataload(0x520), f_q))
mstore(0x7c0, mod(calldataload(0x540), f_q))
mstore(0x7e0, mod(calldataload(0x560), f_q))
mstore(0x800, mod(calldataload(0x580), f_q))
mstore(0x820, mod(calldataload(0x5a0), f_q))
mstore(0x840, mod(calldataload(0x5c0), f_q))
mstore(0x860, mod(calldataload(0x5e0), f_q))
mstore(0x880, mod(calldataload(0x600), f_q))
mstore(0x8a0, mod(calldataload(0x620), f_q))
mstore(0x8c0, mod(calldataload(0x640), f_q))
mstore(0x8e0, mod(calldataload(0x660), f_q))
mstore(0x900, keccak256(0x560, 928))
{
            let hash := mload(0x900)
            mstore(0x920, mod(hash, f_q))
            mstore(0x940, hash)
        }
mstore8(2400, 1)
mstore(0x960, keccak256(0x940, 33))
{
            let hash := mload(0x960)
            mstore(0x980, mod(hash, f_q))
            mstore(0x9a0, hash)
        }

        {
            let x := calldataload(0x680)
            mstore(0x9c0, x)
            let y := calldataload(0x6a0)
            mstore(0x9e0, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0xa00, keccak256(0x9a0, 96))
{
            let hash := mload(0xa00)
            mstore(0xa20, mod(hash, f_q))
            mstore(0xa40, hash)
        }

        {
            let x := calldataload(0x6c0)
            mstore(0xa60, x)
            let y := calldataload(0x6e0)
            mstore(0xa80, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0xaa0, mulmod(mload(0x540), mload(0x540), f_q))
mstore(0xac0, mulmod(mload(0xaa0), mload(0xaa0), f_q))
mstore(0xae0, mulmod(mload(0xac0), mload(0xac0), f_q))
mstore(0xb00, mulmod(mload(0xae0), mload(0xae0), f_q))
mstore(0xb20, mulmod(mload(0xb00), mload(0xb00), f_q))
mstore(0xb40, mulmod(mload(0xb20), mload(0xb20), f_q))
mstore(0xb60, mulmod(mload(0xb40), mload(0xb40), f_q))
mstore(0xb80, mulmod(mload(0xb60), mload(0xb60), f_q))
mstore(0xba0, mulmod(mload(0xb80), mload(0xb80), f_q))
mstore(0xbc0, mulmod(mload(0xba0), mload(0xba0), f_q))
mstore(0xbe0, mulmod(mload(0xbc0), mload(0xbc0), f_q))
mstore(0xc00, mulmod(mload(0xbe0), mload(0xbe0), f_q))
mstore(0xc20, mulmod(mload(0xc00), mload(0xc00), f_q))
mstore(0xc40, mulmod(mload(0xc20), mload(0xc20), f_q))
mstore(0xc60, mulmod(mload(0xc40), mload(0xc40), f_q))
mstore(0xc80, mulmod(mload(0xc60), mload(0xc60), f_q))
mstore(0xca0, mulmod(mload(0xc80), mload(0xc80), f_q))
mstore(0xcc0, mulmod(mload(0xca0), mload(0xca0), f_q))
mstore(0xce0, addmod(mload(0xcc0), 21888242871839275222246405745257275088548364400416034343698204186575808495616, f_q))
mstore(0xd00, mulmod(mload(0xce0), 21888159374819042681065900960079108671330771976540605510559380874944847741953, f_q))
mstore(0xd20, mulmod(mload(0xd00), 7310587191487482613389628690976703164033126240759264491908912333706168173225, f_q))
mstore(0xd40, addmod(mload(0x540), 14577655680351792608856777054280571924515238159656769851789291852869640322392, f_q))
mstore(0xd60, mulmod(mload(0xd00), 9798514389911400568976296423560720718971335345616984532185711118739339214189, f_q))
mstore(0xd80, addmod(mload(0x540), 12089728481927874653270109321696554369577029054799049811512493067836469281428, f_q))
mstore(0xda0, mulmod(mload(0xd00), 21597602092741825212172446666303273253818825148250162481134447417972994544804, f_q))
mstore(0xdc0, addmod(mload(0x540), 290640779097450010073959078954001834729539252165871862563756768602813950813, f_q))
mstore(0xde0, mulmod(mload(0xd00), 5857228514216831962358810454360739186987616060007133076514874820078026801648, f_q))
mstore(0xe00, addmod(mload(0x540), 16031014357622443259887595290896535901560748340408901267183329366497781693969, f_q))
mstore(0xe20, mulmod(mload(0xd00), 15837174511167031493871940795515473313759957271874477857633393696392913897559, f_q))
mstore(0xe40, addmod(mload(0x540), 6051068360672243728374464949741801774788407128541556486064810490182894598058, f_q))
mstore(0xe60, mulmod(mload(0xd00), 11402394834529375719535454173347509224290498423785625657829583372803806900475, f_q))
mstore(0xe80, addmod(mload(0x540), 10485848037309899502710951571909765864257865976630408685868620813772001595142, f_q))
mstore(0xea0, mulmod(mload(0xd00), 6363119021782681274480715230122258277189830284152385293217720612674619714422, f_q))
mstore(0xec0, addmod(mload(0x540), 15525123850056593947765690515135016811358534116263649050480483573901188781195, f_q))
mstore(0xee0, mulmod(mload(0xd00), 1, f_q))
mstore(0xf00, addmod(mload(0x540), 21888242871839275222246405745257275088548364400416034343698204186575808495616, f_q))
{
            let prod := mload(0xd40)

                prod := mulmod(mload(0xd80), prod, f_q)
                mstore(0xf20, prod)
            
                prod := mulmod(mload(0xdc0), prod, f_q)
                mstore(0xf40, prod)
            
                prod := mulmod(mload(0xe00), prod, f_q)
                mstore(0xf60, prod)
            
                prod := mulmod(mload(0xe40), prod, f_q)
                mstore(0xf80, prod)
            
                prod := mulmod(mload(0xe80), prod, f_q)
                mstore(0xfa0, prod)
            
                prod := mulmod(mload(0xec0), prod, f_q)
                mstore(0xfc0, prod)
            
                prod := mulmod(mload(0xf00), prod, f_q)
                mstore(0xfe0, prod)
            
                prod := mulmod(mload(0xce0), prod, f_q)
                mstore(0x1000, prod)
            
        }
mstore(0x1040, 32)
mstore(0x1060, 32)
mstore(0x1080, 32)
mstore(0x10a0, mload(0x1000))
mstore(0x10c0, 21888242871839275222246405745257275088548364400416034343698204186575808495615)
mstore(0x10e0, 21888242871839275222246405745257275088548364400416034343698204186575808495617)
success := and(eq(staticcall(gas(), 0x5, 0x1040, 0xc0, 0x1020, 0x20), 1), success)
{
            
            let inv := mload(0x1020)
            let v
        
                    v := mload(0xce0)
                    mstore(3296, mulmod(mload(0xfe0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xf00)
                    mstore(3840, mulmod(mload(0xfc0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xec0)
                    mstore(3776, mulmod(mload(0xfa0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xe80)
                    mstore(3712, mulmod(mload(0xf80), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xe40)
                    mstore(3648, mulmod(mload(0xf60), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xe00)
                    mstore(3584, mulmod(mload(0xf40), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xdc0)
                    mstore(3520, mulmod(mload(0xf20), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xd80)
                    mstore(3456, mulmod(mload(0xd40), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                mstore(0xd40, inv)

        }
mstore(0x1100, mulmod(mload(0xd20), mload(0xd40), f_q))
mstore(0x1120, mulmod(mload(0xd60), mload(0xd80), f_q))
mstore(0x1140, mulmod(mload(0xda0), mload(0xdc0), f_q))
mstore(0x1160, mulmod(mload(0xde0), mload(0xe00), f_q))
mstore(0x1180, mulmod(mload(0xe20), mload(0xe40), f_q))
mstore(0x11a0, mulmod(mload(0xe60), mload(0xe80), f_q))
mstore(0x11c0, mulmod(mload(0xea0), mload(0xec0), f_q))
mstore(0x11e0, mulmod(mload(0xee0), mload(0xf00), f_q))
mstore(0x1200, mulmod(mload(0x5c0), mload(0x5a0), f_q))
mstore(0x1220, addmod(mload(0x580), mload(0x1200), f_q))
mstore(0x1240, addmod(mload(0x1220), sub(f_q, mload(0x5e0)), f_q))
mstore(0x1260, mulmod(mload(0x1240), mload(0x6e0), f_q))
mstore(0x1280, mulmod(mload(0x420), mload(0x1260), f_q))
mstore(0x12a0, mulmod(mload(0x640), mload(0x620), f_q))
mstore(0x12c0, addmod(mload(0x600), mload(0x12a0), f_q))
mstore(0x12e0, addmod(mload(0x12c0), sub(f_q, mload(0x660)), f_q))
mstore(0x1300, mulmod(mload(0x12e0), mload(0x700), f_q))
mstore(0x1320, addmod(mload(0x1280), mload(0x1300), f_q))
mstore(0x1340, mulmod(mload(0x420), mload(0x1320), f_q))
mstore(0x1360, addmod(1, sub(f_q, mload(0x7c0)), f_q))
mstore(0x1380, mulmod(mload(0x1360), mload(0x11e0), f_q))
mstore(0x13a0, addmod(mload(0x1340), mload(0x1380), f_q))
mstore(0x13c0, mulmod(mload(0x420), mload(0x13a0), f_q))
mstore(0x13e0, mulmod(mload(0x820), mload(0x820), f_q))
mstore(0x1400, addmod(mload(0x13e0), sub(f_q, mload(0x820)), f_q))
mstore(0x1420, mulmod(mload(0x1400), mload(0x1100), f_q))
mstore(0x1440, addmod(mload(0x13c0), mload(0x1420), f_q))
mstore(0x1460, mulmod(mload(0x420), mload(0x1440), f_q))
mstore(0x1480, addmod(mload(0x820), sub(f_q, mload(0x800)), f_q))
mstore(0x14a0, mulmod(mload(0x1480), mload(0x11e0), f_q))
mstore(0x14c0, addmod(mload(0x1460), mload(0x14a0), f_q))
mstore(0x14e0, mulmod(mload(0x420), mload(0x14c0), f_q))
mstore(0x1500, addmod(1, sub(f_q, mload(0x1100)), f_q))
mstore(0x1520, addmod(mload(0x1120), mload(0x1140), f_q))
mstore(0x1540, addmod(mload(0x1520), mload(0x1160), f_q))
mstore(0x1560, addmod(mload(0x1540), mload(0x1180), f_q))
mstore(0x1580, addmod(mload(0x1560), mload(0x11a0), f_q))
mstore(0x15a0, addmod(mload(0x1580), mload(0x11c0), f_q))
mstore(0x15c0, addmod(mload(0x1500), sub(f_q, mload(0x15a0)), f_q))
mstore(0x15e0, mulmod(mload(0x740), mload(0x260), f_q))
mstore(0x1600, addmod(mload(0x6a0), mload(0x15e0), f_q))
mstore(0x1620, addmod(mload(0x1600), mload(0x2c0), f_q))
mstore(0x1640, mulmod(mload(0x760), mload(0x260), f_q))
mstore(0x1660, addmod(mload(0x580), mload(0x1640), f_q))
mstore(0x1680, addmod(mload(0x1660), mload(0x2c0), f_q))
mstore(0x16a0, mulmod(mload(0x1680), mload(0x1620), f_q))
mstore(0x16c0, mulmod(mload(0x16a0), mload(0x7e0), f_q))
mstore(0x16e0, mulmod(1, mload(0x260), f_q))
mstore(0x1700, mulmod(mload(0x540), mload(0x16e0), f_q))
mstore(0x1720, addmod(mload(0x6a0), mload(0x1700), f_q))
mstore(0x1740, addmod(mload(0x1720), mload(0x2c0), f_q))
mstore(0x1760, mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, mload(0x260), f_q))
mstore(0x1780, mulmod(mload(0x540), mload(0x1760), f_q))
mstore(0x17a0, addmod(mload(0x580), mload(0x1780), f_q))
mstore(0x17c0, addmod(mload(0x17a0), mload(0x2c0), f_q))
mstore(0x17e0, mulmod(mload(0x17c0), mload(0x1740), f_q))
mstore(0x1800, mulmod(mload(0x17e0), mload(0x7c0), f_q))
mstore(0x1820, addmod(mload(0x16c0), sub(f_q, mload(0x1800)), f_q))
mstore(0x1840, mulmod(mload(0x1820), mload(0x15c0), f_q))
mstore(0x1860, addmod(mload(0x14e0), mload(0x1840), f_q))
mstore(0x1880, mulmod(mload(0x420), mload(0x1860), f_q))
mstore(0x18a0, mulmod(mload(0x780), mload(0x260), f_q))
mstore(0x18c0, addmod(mload(0x600), mload(0x18a0), f_q))
mstore(0x18e0, addmod(mload(0x18c0), mload(0x2c0), f_q))
mstore(0x1900, mulmod(mload(0x7a0), mload(0x260), f_q))
mstore(0x1920, addmod(mload(0x680), mload(0x1900), f_q))
mstore(0x1940, addmod(mload(0x1920), mload(0x2c0), f_q))
mstore(0x1960, mulmod(mload(0x1940), mload(0x18e0), f_q))
mstore(0x1980, mulmod(mload(0x1960), mload(0x840), f_q))
mstore(0x19a0, mulmod(8910878055287538404433155982483128285667088683464058436815641868457422632747, mload(0x260), f_q))
mstore(0x19c0, mulmod(mload(0x540), mload(0x19a0), f_q))
mstore(0x19e0, addmod(mload(0x600), mload(0x19c0), f_q))
mstore(0x1a00, addmod(mload(0x19e0), mload(0x2c0), f_q))
mstore(0x1a20, mulmod(11166246659983828508719468090013646171463329086121580628794302409516816350802, mload(0x260), f_q))
mstore(0x1a40, mulmod(mload(0x540), mload(0x1a20), f_q))
mstore(0x1a60, addmod(mload(0x680), mload(0x1a40), f_q))
mstore(0x1a80, addmod(mload(0x1a60), mload(0x2c0), f_q))
mstore(0x1aa0, mulmod(mload(0x1a80), mload(0x1a00), f_q))
mstore(0x1ac0, mulmod(mload(0x1aa0), mload(0x820), f_q))
mstore(0x1ae0, addmod(mload(0x1980), sub(f_q, mload(0x1ac0)), f_q))
mstore(0x1b00, mulmod(mload(0x1ae0), mload(0x15c0), f_q))
mstore(0x1b20, addmod(mload(0x1880), mload(0x1b00), f_q))
mstore(0x1b40, mulmod(mload(0x420), mload(0x1b20), f_q))
mstore(0x1b60, addmod(1, sub(f_q, mload(0x860)), f_q))
mstore(0x1b80, mulmod(mload(0x1b60), mload(0x11e0), f_q))
mstore(0x1ba0, addmod(mload(0x1b40), mload(0x1b80), f_q))
mstore(0x1bc0, mulmod(mload(0x420), mload(0x1ba0), f_q))
mstore(0x1be0, mulmod(mload(0x860), mload(0x860), f_q))
mstore(0x1c00, addmod(mload(0x1be0), sub(f_q, mload(0x860)), f_q))
mstore(0x1c20, mulmod(mload(0x1c00), mload(0x1100), f_q))
mstore(0x1c40, addmod(mload(0x1bc0), mload(0x1c20), f_q))
mstore(0x1c60, mulmod(mload(0x420), mload(0x1c40), f_q))
mstore(0x1c80, addmod(mload(0x8a0), mload(0x260), f_q))
mstore(0x1ca0, mulmod(mload(0x1c80), mload(0x880), f_q))
mstore(0x1cc0, addmod(mload(0x8e0), mload(0x2c0), f_q))
mstore(0x1ce0, mulmod(mload(0x1cc0), mload(0x1ca0), f_q))
mstore(0x1d00, addmod(mload(0x680), mload(0x260), f_q))
mstore(0x1d20, mulmod(mload(0x1d00), mload(0x860), f_q))
mstore(0x1d40, addmod(mload(0x6c0), mload(0x2c0), f_q))
mstore(0x1d60, mulmod(mload(0x1d40), mload(0x1d20), f_q))
mstore(0x1d80, addmod(mload(0x1ce0), sub(f_q, mload(0x1d60)), f_q))
mstore(0x1da0, mulmod(mload(0x1d80), mload(0x15c0), f_q))
mstore(0x1dc0, addmod(mload(0x1c60), mload(0x1da0), f_q))
mstore(0x1de0, mulmod(mload(0x420), mload(0x1dc0), f_q))
mstore(0x1e00, addmod(mload(0x8a0), sub(f_q, mload(0x8e0)), f_q))
mstore(0x1e20, mulmod(mload(0x1e00), mload(0x11e0), f_q))
mstore(0x1e40, addmod(mload(0x1de0), mload(0x1e20), f_q))
mstore(0x1e60, mulmod(mload(0x420), mload(0x1e40), f_q))
mstore(0x1e80, mulmod(mload(0x1e00), mload(0x15c0), f_q))
mstore(0x1ea0, addmod(mload(0x8a0), sub(f_q, mload(0x8c0)), f_q))
mstore(0x1ec0, mulmod(mload(0x1ea0), mload(0x1e80), f_q))
mstore(0x1ee0, addmod(mload(0x1e60), mload(0x1ec0), f_q))
mstore(0x1f00, mulmod(mload(0xcc0), mload(0xcc0), f_q))
mstore(0x1f20, mulmod(mload(0x1f00), mload(0xcc0), f_q))
mstore(0x1f40, mulmod(1, mload(0xcc0), f_q))
mstore(0x1f60, mulmod(1, mload(0x1f00), f_q))
mstore(0x1f80, mulmod(mload(0x1ee0), mload(0xce0), f_q))
mstore(0x1fa0, mulmod(mload(0xaa0), mload(0x540), f_q))
mstore(0x1fc0, mulmod(mload(0x1fa0), mload(0x540), f_q))
mstore(0x1fe0, mulmod(mload(0x540), 7310587191487482613389628690976703164033126240759264491908912333706168173225, f_q))
mstore(0x2000, addmod(mload(0xa20), sub(f_q, mload(0x1fe0)), f_q))
mstore(0x2020, mulmod(mload(0x540), 6363119021782681274480715230122258277189830284152385293217720612674619714422, f_q))
mstore(0x2040, addmod(mload(0xa20), sub(f_q, mload(0x2020)), f_q))
mstore(0x2060, mulmod(mload(0x540), 1, f_q))
mstore(0x2080, addmod(mload(0xa20), sub(f_q, mload(0x2060)), f_q))
mstore(0x20a0, mulmod(mload(0x540), 6955697244493336113861667751840378876927906302623587437721024018233754910398, f_q))
mstore(0x20c0, addmod(mload(0xa20), sub(f_q, mload(0x20a0)), f_q))
mstore(0x20e0, mulmod(mload(0x540), 21846745818185811051373434299876022191132089169516983080959277716660228899818, f_q))
mstore(0x2100, addmod(mload(0xa20), sub(f_q, mload(0x20e0)), f_q))
mstore(0x2120, mulmod(mload(0x540), 13526759757306252939732186602630155490343117803221487512984160143178057306805, f_q))
mstore(0x2140, addmod(mload(0xa20), sub(f_q, mload(0x2120)), f_q))
mstore(0x2160, mulmod(2940864004678975696316873683451526288601574908606966186364026277868707679642, mload(0x1fa0), f_q))
mstore(0x2180, mulmod(mload(0x2160), 1, f_q))
{
            let result := mulmod(mload(0xa20), mload(0x2160), f_q)
result := addmod(mulmod(mload(0x540), sub(f_q, mload(0x2180)), f_q), result, f_q)
mstore(8608, result)
        }
mstore(0x21c0, mulmod(3780184929546207794165793425726688506491165310656918727921268383959469598456, mload(0x1fa0), f_q))
mstore(0x21e0, mulmod(mload(0x21c0), 6955697244493336113861667751840378876927906302623587437721024018233754910398, f_q))
{
            let result := mulmod(mload(0xa20), mload(0x21c0), f_q)
result := addmod(mulmod(mload(0x540), sub(f_q, mload(0x21e0)), f_q), result, f_q)
mstore(8704, result)
        }
mstore(0x2220, mulmod(15988440449117113657962678264155427359263359440478972105692146429637038953160, mload(0x1fa0), f_q))
mstore(0x2240, mulmod(mload(0x2220), 21846745818185811051373434299876022191132089169516983080959277716660228899818, f_q))
{
            let result := mulmod(mload(0xa20), mload(0x2220), f_q)
result := addmod(mulmod(mload(0x540), sub(f_q, mload(0x2240)), f_q), result, f_q)
mstore(8800, result)
        }
mstore(0x2280, mulmod(18220982760928406788147627975587442470177662144847785908405976500286566091551, mload(0x1fa0), f_q))
mstore(0x22a0, mulmod(mload(0x2280), 13526759757306252939732186602630155490343117803221487512984160143178057306805, f_q))
{
            let result := mulmod(mload(0xa20), mload(0x2280), f_q)
result := addmod(mulmod(mload(0x540), sub(f_q, mload(0x22a0)), f_q), result, f_q)
mstore(8896, result)
        }
mstore(0x22e0, mulmod(1, mload(0x2080), f_q))
mstore(0x2300, mulmod(mload(0x22e0), mload(0x20c0), f_q))
mstore(0x2320, mulmod(mload(0x2300), mload(0x2100), f_q))
mstore(0x2340, mulmod(mload(0x2320), mload(0x2140), f_q))
{
            let result := mulmod(mload(0xa20), 1, f_q)
result := addmod(mulmod(mload(0x540), 21888242871839275222246405745257275088548364400416034343698204186575808495616, f_q), result, f_q)
mstore(9056, result)
        }
mstore(0x2380, mulmod(17420472825769857063971405726000913766558667202650166946253978953375224626184, mload(0xaa0), f_q))
mstore(0x23a0, mulmod(mload(0x2380), 1, f_q))
{
            let result := mulmod(mload(0xa20), mload(0x2380), f_q)
result := addmod(mulmod(mload(0x540), sub(f_q, mload(0x23a0)), f_q), result, f_q)
mstore(9152, result)
        }
mstore(0x23e0, mulmod(12403121375268556981925098815451625759265973762035675602961454913393302948456, mload(0xaa0), f_q))
mstore(0x2400, mulmod(mload(0x23e0), 6955697244493336113861667751840378876927906302623587437721024018233754910398, f_q))
{
            let result := mulmod(mload(0xa20), mload(0x23e0), f_q)
result := addmod(mulmod(mload(0x540), sub(f_q, mload(0x2400)), f_q), result, f_q)
mstore(9248, result)
        }
mstore(0x2440, mulmod(11026988883822566352833937753519824719181511317208835361160053691376277278989, mload(0xaa0), f_q))
mstore(0x2460, mulmod(mload(0x2440), 7310587191487482613389628690976703164033126240759264491908912333706168173225, f_q))
{
            let result := mulmod(mload(0xa20), mload(0x2440), f_q)
result := addmod(mulmod(mload(0x540), sub(f_q, mload(0x2460)), f_q), result, f_q)
mstore(9344, result)
        }
mstore(0x24a0, mulmod(mload(0x2300), mload(0x2000), f_q))
mstore(0x24c0, mulmod(14932545627345939108384737993416896211620458097792446905977180168342053585220, mload(0x540), f_q))
mstore(0x24e0, mulmod(mload(0x24c0), 1, f_q))
{
            let result := mulmod(mload(0xa20), mload(0x24c0), f_q)
result := addmod(mulmod(mload(0x540), sub(f_q, mload(0x24e0)), f_q), result, f_q)
mstore(9472, result)
        }
mstore(0x2520, mulmod(6955697244493336113861667751840378876927906302623587437721024018233754910397, mload(0x540), f_q))
mstore(0x2540, mulmod(mload(0x2520), 6955697244493336113861667751840378876927906302623587437721024018233754910398, f_q))
{
            let result := mulmod(mload(0xa20), mload(0x2520), f_q)
result := addmod(mulmod(mload(0x540), sub(f_q, mload(0x2540)), f_q), result, f_q)
mstore(9568, result)
        }
mstore(0x2580, mulmod(15525123850056593947765690515135016811358534116263649050480483573901188781196, mload(0x540), f_q))
mstore(0x25a0, mulmod(mload(0x2580), 1, f_q))
{
            let result := mulmod(mload(0xa20), mload(0x2580), f_q)
result := addmod(mulmod(mload(0x540), sub(f_q, mload(0x25a0)), f_q), result, f_q)
mstore(9664, result)
        }
mstore(0x25e0, mulmod(6363119021782681274480715230122258277189830284152385293217720612674619714421, mload(0x540), f_q))
mstore(0x2600, mulmod(mload(0x25e0), 6363119021782681274480715230122258277189830284152385293217720612674619714422, f_q))
{
            let result := mulmod(mload(0xa20), mload(0x25e0), f_q)
result := addmod(mulmod(mload(0x540), sub(f_q, mload(0x2600)), f_q), result, f_q)
mstore(9760, result)
        }
mstore(0x2640, mulmod(mload(0x22e0), mload(0x2040), f_q))
{
            let prod := mload(0x21a0)

                prod := mulmod(mload(0x2200), prod, f_q)
                mstore(0x2660, prod)
            
                prod := mulmod(mload(0x2260), prod, f_q)
                mstore(0x2680, prod)
            
                prod := mulmod(mload(0x22c0), prod, f_q)
                mstore(0x26a0, prod)
            
                prod := mulmod(mload(0x2360), prod, f_q)
                mstore(0x26c0, prod)
            
                prod := mulmod(mload(0x22e0), prod, f_q)
                mstore(0x26e0, prod)
            
                prod := mulmod(mload(0x23c0), prod, f_q)
                mstore(0x2700, prod)
            
                prod := mulmod(mload(0x2420), prod, f_q)
                mstore(0x2720, prod)
            
                prod := mulmod(mload(0x2480), prod, f_q)
                mstore(0x2740, prod)
            
                prod := mulmod(mload(0x24a0), prod, f_q)
                mstore(0x2760, prod)
            
                prod := mulmod(mload(0x2500), prod, f_q)
                mstore(0x2780, prod)
            
                prod := mulmod(mload(0x2560), prod, f_q)
                mstore(0x27a0, prod)
            
                prod := mulmod(mload(0x2300), prod, f_q)
                mstore(0x27c0, prod)
            
                prod := mulmod(mload(0x25c0), prod, f_q)
                mstore(0x27e0, prod)
            
                prod := mulmod(mload(0x2620), prod, f_q)
                mstore(0x2800, prod)
            
                prod := mulmod(mload(0x2640), prod, f_q)
                mstore(0x2820, prod)
            
        }
mstore(0x2860, 32)
mstore(0x2880, 32)
mstore(0x28a0, 32)
mstore(0x28c0, mload(0x2820))
mstore(0x28e0, 21888242871839275222246405745257275088548364400416034343698204186575808495615)
mstore(0x2900, 21888242871839275222246405745257275088548364400416034343698204186575808495617)
success := and(eq(staticcall(gas(), 0x5, 0x2860, 0xc0, 0x2840, 0x20), 1), success)
{
            
            let inv := mload(0x2840)
            let v
        
                    v := mload(0x2640)
                    mstore(9792, mulmod(mload(0x2800), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2620)
                    mstore(9760, mulmod(mload(0x27e0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x25c0)
                    mstore(9664, mulmod(mload(0x27c0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2300)
                    mstore(8960, mulmod(mload(0x27a0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2560)
                    mstore(9568, mulmod(mload(0x2780), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2500)
                    mstore(9472, mulmod(mload(0x2760), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x24a0)
                    mstore(9376, mulmod(mload(0x2740), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2480)
                    mstore(9344, mulmod(mload(0x2720), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2420)
                    mstore(9248, mulmod(mload(0x2700), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x23c0)
                    mstore(9152, mulmod(mload(0x26e0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x22e0)
                    mstore(8928, mulmod(mload(0x26c0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2360)
                    mstore(9056, mulmod(mload(0x26a0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x22c0)
                    mstore(8896, mulmod(mload(0x2680), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2260)
                    mstore(8800, mulmod(mload(0x2660), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2200)
                    mstore(8704, mulmod(mload(0x21a0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                mstore(0x21a0, inv)

        }
{
            let result := mload(0x21a0)
result := addmod(mload(0x2200), result, f_q)
result := addmod(mload(0x2260), result, f_q)
result := addmod(mload(0x22c0), result, f_q)
mstore(10528, result)
        }
mstore(0x2940, mulmod(mload(0x2340), mload(0x22e0), f_q))
{
            let result := mload(0x2360)
mstore(10592, result)
        }
mstore(0x2980, mulmod(mload(0x2340), mload(0x24a0), f_q))
{
            let result := mload(0x23c0)
result := addmod(mload(0x2420), result, f_q)
result := addmod(mload(0x2480), result, f_q)
mstore(10656, result)
        }
mstore(0x29c0, mulmod(mload(0x2340), mload(0x2300), f_q))
{
            let result := mload(0x2500)
result := addmod(mload(0x2560), result, f_q)
mstore(10720, result)
        }
mstore(0x2a00, mulmod(mload(0x2340), mload(0x2640), f_q))
{
            let result := mload(0x25c0)
result := addmod(mload(0x2620), result, f_q)
mstore(10784, result)
        }
{
            let prod := mload(0x2920)

                prod := mulmod(mload(0x2960), prod, f_q)
                mstore(0x2a40, prod)
            
                prod := mulmod(mload(0x29a0), prod, f_q)
                mstore(0x2a60, prod)
            
                prod := mulmod(mload(0x29e0), prod, f_q)
                mstore(0x2a80, prod)
            
                prod := mulmod(mload(0x2a20), prod, f_q)
                mstore(0x2aa0, prod)
            
        }
mstore(0x2ae0, 32)
mstore(0x2b00, 32)
mstore(0x2b20, 32)
mstore(0x2b40, mload(0x2aa0))
mstore(0x2b60, 21888242871839275222246405745257275088548364400416034343698204186575808495615)
mstore(0x2b80, 21888242871839275222246405745257275088548364400416034343698204186575808495617)
success := and(eq(staticcall(gas(), 0x5, 0x2ae0, 0xc0, 0x2ac0, 0x20), 1), success)
{
            
            let inv := mload(0x2ac0)
            let v
        
                    v := mload(0x2a20)
                    mstore(10784, mulmod(mload(0x2a80), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x29e0)
                    mstore(10720, mulmod(mload(0x2a60), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x29a0)
                    mstore(10656, mulmod(mload(0x2a40), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2960)
                    mstore(10592, mulmod(mload(0x2920), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                mstore(0x2920, inv)

        }
mstore(0x2ba0, mulmod(mload(0x2940), mload(0x2960), f_q))
mstore(0x2bc0, mulmod(mload(0x2980), mload(0x29a0), f_q))
mstore(0x2be0, mulmod(mload(0x29c0), mload(0x29e0), f_q))
mstore(0x2c00, mulmod(mload(0x2a00), mload(0x2a20), f_q))
mstore(0x2c20, mulmod(mload(0x920), mload(0x920), f_q))
mstore(0x2c40, mulmod(mload(0x2c20), mload(0x920), f_q))
mstore(0x2c60, mulmod(mload(0x2c40), mload(0x920), f_q))
mstore(0x2c80, mulmod(mload(0x2c60), mload(0x920), f_q))
mstore(0x2ca0, mulmod(mload(0x2c80), mload(0x920), f_q))
mstore(0x2cc0, mulmod(mload(0x2ca0), mload(0x920), f_q))
mstore(0x2ce0, mulmod(mload(0x2cc0), mload(0x920), f_q))
mstore(0x2d00, mulmod(mload(0x2ce0), mload(0x920), f_q))
mstore(0x2d20, mulmod(mload(0x2d00), mload(0x920), f_q))
mstore(0x2d40, mulmod(mload(0x2d20), mload(0x920), f_q))
mstore(0x2d60, mulmod(mload(0x2d40), mload(0x920), f_q))
mstore(0x2d80, mulmod(mload(0x980), mload(0x980), f_q))
mstore(0x2da0, mulmod(mload(0x2d80), mload(0x980), f_q))
mstore(0x2dc0, mulmod(mload(0x2da0), mload(0x980), f_q))
mstore(0x2de0, mulmod(mload(0x2dc0), mload(0x980), f_q))
{
            let result := mulmod(mload(0x580), mload(0x21a0), f_q)
result := addmod(mulmod(mload(0x5a0), mload(0x2200), f_q), result, f_q)
result := addmod(mulmod(mload(0x5c0), mload(0x2260), f_q), result, f_q)
result := addmod(mulmod(mload(0x5e0), mload(0x22c0), f_q), result, f_q)
mstore(11776, result)
        }
mstore(0x2e20, mulmod(mload(0x2e00), mload(0x2920), f_q))
mstore(0x2e40, mulmod(sub(f_q, mload(0x2e20)), 1, f_q))
{
            let result := mulmod(mload(0x600), mload(0x21a0), f_q)
result := addmod(mulmod(mload(0x620), mload(0x2200), f_q), result, f_q)
result := addmod(mulmod(mload(0x640), mload(0x2260), f_q), result, f_q)
result := addmod(mulmod(mload(0x660), mload(0x22c0), f_q), result, f_q)
mstore(11872, result)
        }
mstore(0x2e80, mulmod(mload(0x2e60), mload(0x2920), f_q))
mstore(0x2ea0, mulmod(sub(f_q, mload(0x2e80)), mload(0x920), f_q))
mstore(0x2ec0, mulmod(1, mload(0x920), f_q))
mstore(0x2ee0, addmod(mload(0x2e40), mload(0x2ea0), f_q))
mstore(0x2f00, mulmod(mload(0x2ee0), 1, f_q))
mstore(0x2f20, mulmod(mload(0x2ec0), 1, f_q))
mstore(0x2f40, mulmod(1, mload(0x2940), f_q))
{
            let result := mulmod(mload(0x680), mload(0x2360), f_q)
mstore(12128, result)
        }
mstore(0x2f80, mulmod(mload(0x2f60), mload(0x2ba0), f_q))
mstore(0x2fa0, mulmod(sub(f_q, mload(0x2f80)), 1, f_q))
mstore(0x2fc0, mulmod(mload(0x2f40), 1, f_q))
{
            let result := mulmod(mload(0x8e0), mload(0x2360), f_q)
mstore(12256, result)
        }
mstore(0x3000, mulmod(mload(0x2fe0), mload(0x2ba0), f_q))
mstore(0x3020, mulmod(sub(f_q, mload(0x3000)), mload(0x920), f_q))
mstore(0x3040, mulmod(mload(0x2f40), mload(0x920), f_q))
mstore(0x3060, addmod(mload(0x2fa0), mload(0x3020), f_q))
{
            let result := mulmod(mload(0x6a0), mload(0x2360), f_q)
mstore(12416, result)
        }
mstore(0x30a0, mulmod(mload(0x3080), mload(0x2ba0), f_q))
mstore(0x30c0, mulmod(sub(f_q, mload(0x30a0)), mload(0x2c20), f_q))
mstore(0x30e0, mulmod(mload(0x2f40), mload(0x2c20), f_q))
mstore(0x3100, addmod(mload(0x3060), mload(0x30c0), f_q))
{
            let result := mulmod(mload(0x6c0), mload(0x2360), f_q)
mstore(12576, result)
        }
mstore(0x3140, mulmod(mload(0x3120), mload(0x2ba0), f_q))
mstore(0x3160, mulmod(sub(f_q, mload(0x3140)), mload(0x2c40), f_q))
mstore(0x3180, mulmod(mload(0x2f40), mload(0x2c40), f_q))
mstore(0x31a0, addmod(mload(0x3100), mload(0x3160), f_q))
{
            let result := mulmod(mload(0x6e0), mload(0x2360), f_q)
mstore(12736, result)
        }
mstore(0x31e0, mulmod(mload(0x31c0), mload(0x2ba0), f_q))
mstore(0x3200, mulmod(sub(f_q, mload(0x31e0)), mload(0x2c60), f_q))
mstore(0x3220, mulmod(mload(0x2f40), mload(0x2c60), f_q))
mstore(0x3240, addmod(mload(0x31a0), mload(0x3200), f_q))
{
            let result := mulmod(mload(0x700), mload(0x2360), f_q)
mstore(12896, result)
        }
mstore(0x3280, mulmod(mload(0x3260), mload(0x2ba0), f_q))
mstore(0x32a0, mulmod(sub(f_q, mload(0x3280)), mload(0x2c80), f_q))
mstore(0x32c0, mulmod(mload(0x2f40), mload(0x2c80), f_q))
mstore(0x32e0, addmod(mload(0x3240), mload(0x32a0), f_q))
{
            let result := mulmod(mload(0x740), mload(0x2360), f_q)
mstore(13056, result)
        }
mstore(0x3320, mulmod(mload(0x3300), mload(0x2ba0), f_q))
mstore(0x3340, mulmod(sub(f_q, mload(0x3320)), mload(0x2ca0), f_q))
mstore(0x3360, mulmod(mload(0x2f40), mload(0x2ca0), f_q))
mstore(0x3380, addmod(mload(0x32e0), mload(0x3340), f_q))
{
            let result := mulmod(mload(0x760), mload(0x2360), f_q)
mstore(13216, result)
        }
mstore(0x33c0, mulmod(mload(0x33a0), mload(0x2ba0), f_q))
mstore(0x33e0, mulmod(sub(f_q, mload(0x33c0)), mload(0x2cc0), f_q))
mstore(0x3400, mulmod(mload(0x2f40), mload(0x2cc0), f_q))
mstore(0x3420, addmod(mload(0x3380), mload(0x33e0), f_q))
{
            let result := mulmod(mload(0x780), mload(0x2360), f_q)
mstore(13376, result)
        }
mstore(0x3460, mulmod(mload(0x3440), mload(0x2ba0), f_q))
mstore(0x3480, mulmod(sub(f_q, mload(0x3460)), mload(0x2ce0), f_q))
mstore(0x34a0, mulmod(mload(0x2f40), mload(0x2ce0), f_q))
mstore(0x34c0, addmod(mload(0x3420), mload(0x3480), f_q))
{
            let result := mulmod(mload(0x7a0), mload(0x2360), f_q)
mstore(13536, result)
        }
mstore(0x3500, mulmod(mload(0x34e0), mload(0x2ba0), f_q))
mstore(0x3520, mulmod(sub(f_q, mload(0x3500)), mload(0x2d00), f_q))
mstore(0x3540, mulmod(mload(0x2f40), mload(0x2d00), f_q))
mstore(0x3560, addmod(mload(0x34c0), mload(0x3520), f_q))
mstore(0x3580, mulmod(mload(0x1f40), mload(0x2940), f_q))
mstore(0x35a0, mulmod(mload(0x1f60), mload(0x2940), f_q))
{
            let result := mulmod(mload(0x1f80), mload(0x2360), f_q)
mstore(13760, result)
        }
mstore(0x35e0, mulmod(mload(0x35c0), mload(0x2ba0), f_q))
mstore(0x3600, mulmod(sub(f_q, mload(0x35e0)), mload(0x2d20), f_q))
mstore(0x3620, mulmod(mload(0x2f40), mload(0x2d20), f_q))
mstore(0x3640, mulmod(mload(0x3580), mload(0x2d20), f_q))
mstore(0x3660, mulmod(mload(0x35a0), mload(0x2d20), f_q))
mstore(0x3680, addmod(mload(0x3560), mload(0x3600), f_q))
{
            let result := mulmod(mload(0x720), mload(0x2360), f_q)
mstore(13984, result)
        }
mstore(0x36c0, mulmod(mload(0x36a0), mload(0x2ba0), f_q))
mstore(0x36e0, mulmod(sub(f_q, mload(0x36c0)), mload(0x2d40), f_q))
mstore(0x3700, mulmod(mload(0x2f40), mload(0x2d40), f_q))
mstore(0x3720, addmod(mload(0x3680), mload(0x36e0), f_q))
mstore(0x3740, mulmod(mload(0x3720), mload(0x980), f_q))
mstore(0x3760, mulmod(mload(0x2fc0), mload(0x980), f_q))
mstore(0x3780, mulmod(mload(0x3040), mload(0x980), f_q))
mstore(0x37a0, mulmod(mload(0x30e0), mload(0x980), f_q))
mstore(0x37c0, mulmod(mload(0x3180), mload(0x980), f_q))
mstore(0x37e0, mulmod(mload(0x3220), mload(0x980), f_q))
mstore(0x3800, mulmod(mload(0x32c0), mload(0x980), f_q))
mstore(0x3820, mulmod(mload(0x3360), mload(0x980), f_q))
mstore(0x3840, mulmod(mload(0x3400), mload(0x980), f_q))
mstore(0x3860, mulmod(mload(0x34a0), mload(0x980), f_q))
mstore(0x3880, mulmod(mload(0x3540), mload(0x980), f_q))
mstore(0x38a0, mulmod(mload(0x3620), mload(0x980), f_q))
mstore(0x38c0, mulmod(mload(0x3640), mload(0x980), f_q))
mstore(0x38e0, mulmod(mload(0x3660), mload(0x980), f_q))
mstore(0x3900, mulmod(mload(0x3700), mload(0x980), f_q))
mstore(0x3920, addmod(mload(0x2f00), mload(0x3740), f_q))
mstore(0x3940, mulmod(1, mload(0x2980), f_q))
{
            let result := mulmod(mload(0x7c0), mload(0x23c0), f_q)
result := addmod(mulmod(mload(0x7e0), mload(0x2420), f_q), result, f_q)
result := addmod(mulmod(mload(0x800), mload(0x2480), f_q), result, f_q)
mstore(14688, result)
        }
mstore(0x3980, mulmod(mload(0x3960), mload(0x2bc0), f_q))
mstore(0x39a0, mulmod(sub(f_q, mload(0x3980)), 1, f_q))
mstore(0x39c0, mulmod(mload(0x3940), 1, f_q))
mstore(0x39e0, mulmod(mload(0x39a0), mload(0x2d80), f_q))
mstore(0x3a00, mulmod(mload(0x39c0), mload(0x2d80), f_q))
mstore(0x3a20, addmod(mload(0x3920), mload(0x39e0), f_q))
mstore(0x3a40, mulmod(1, mload(0x29c0), f_q))
{
            let result := mulmod(mload(0x820), mload(0x2500), f_q)
result := addmod(mulmod(mload(0x840), mload(0x2560), f_q), result, f_q)
mstore(14944, result)
        }
mstore(0x3a80, mulmod(mload(0x3a60), mload(0x2be0), f_q))
mstore(0x3aa0, mulmod(sub(f_q, mload(0x3a80)), 1, f_q))
mstore(0x3ac0, mulmod(mload(0x3a40), 1, f_q))
{
            let result := mulmod(mload(0x860), mload(0x2500), f_q)
result := addmod(mulmod(mload(0x880), mload(0x2560), f_q), result, f_q)
mstore(15072, result)
        }
mstore(0x3b00, mulmod(mload(0x3ae0), mload(0x2be0), f_q))
mstore(0x3b20, mulmod(sub(f_q, mload(0x3b00)), mload(0x920), f_q))
mstore(0x3b40, mulmod(mload(0x3a40), mload(0x920), f_q))
mstore(0x3b60, addmod(mload(0x3aa0), mload(0x3b20), f_q))
mstore(0x3b80, mulmod(mload(0x3b60), mload(0x2da0), f_q))
mstore(0x3ba0, mulmod(mload(0x3ac0), mload(0x2da0), f_q))
mstore(0x3bc0, mulmod(mload(0x3b40), mload(0x2da0), f_q))
mstore(0x3be0, addmod(mload(0x3a20), mload(0x3b80), f_q))
mstore(0x3c00, mulmod(1, mload(0x2a00), f_q))
{
            let result := mulmod(mload(0x8a0), mload(0x25c0), f_q)
result := addmod(mulmod(mload(0x8c0), mload(0x2620), f_q), result, f_q)
mstore(15392, result)
        }
mstore(0x3c40, mulmod(mload(0x3c20), mload(0x2c00), f_q))
mstore(0x3c60, mulmod(sub(f_q, mload(0x3c40)), 1, f_q))
mstore(0x3c80, mulmod(mload(0x3c00), 1, f_q))
mstore(0x3ca0, mulmod(mload(0x3c60), mload(0x2dc0), f_q))
mstore(0x3cc0, mulmod(mload(0x3c80), mload(0x2dc0), f_q))
mstore(0x3ce0, addmod(mload(0x3be0), mload(0x3ca0), f_q))
mstore(0x3d00, mulmod(1, mload(0x2340), f_q))
mstore(0x3d20, mulmod(1, mload(0xa20), f_q))
mstore(0x3d40, 0x0000000000000000000000000000000000000000000000000000000000000001)
                    mstore(0x3d60, 0x0000000000000000000000000000000000000000000000000000000000000002)
mstore(0x3d80, mload(0x3ce0))
success := and(eq(staticcall(gas(), 0x7, 0x3d40, 0x60, 0x3d40, 0x40), 1), success)
mstore(0x3da0, mload(0x3d40))
                    mstore(0x3dc0, mload(0x3d60))
mstore(0x3de0, mload(0xa0))
                    mstore(0x3e00, mload(0xc0))
success := and(eq(staticcall(gas(), 0x6, 0x3da0, 0x80, 0x3da0, 0x40), 1), success)
mstore(0x3e20, mload(0xe0))
                    mstore(0x3e40, mload(0x100))
mstore(0x3e60, mload(0x2f20))
success := and(eq(staticcall(gas(), 0x7, 0x3e20, 0x60, 0x3e20, 0x40), 1), success)
mstore(0x3e80, mload(0x3da0))
                    mstore(0x3ea0, mload(0x3dc0))
mstore(0x3ec0, mload(0x3e20))
                    mstore(0x3ee0, mload(0x3e40))
success := and(eq(staticcall(gas(), 0x6, 0x3e80, 0x80, 0x3e80, 0x40), 1), success)
mstore(0x3f00, mload(0x120))
                    mstore(0x3f20, mload(0x140))
mstore(0x3f40, mload(0x3760))
success := and(eq(staticcall(gas(), 0x7, 0x3f00, 0x60, 0x3f00, 0x40), 1), success)
mstore(0x3f60, mload(0x3e80))
                    mstore(0x3f80, mload(0x3ea0))
mstore(0x3fa0, mload(0x3f00))
                    mstore(0x3fc0, mload(0x3f20))
success := and(eq(staticcall(gas(), 0x6, 0x3f60, 0x80, 0x3f60, 0x40), 1), success)
mstore(0x3fe0, mload(0x200))
                    mstore(0x4000, mload(0x220))
mstore(0x4020, mload(0x3780))
success := and(eq(staticcall(gas(), 0x7, 0x3fe0, 0x60, 0x3fe0, 0x40), 1), success)
mstore(0x4040, mload(0x3f60))
                    mstore(0x4060, mload(0x3f80))
mstore(0x4080, mload(0x3fe0))
                    mstore(0x40a0, mload(0x4000))
success := and(eq(staticcall(gas(), 0x6, 0x4040, 0x80, 0x4040, 0x40), 1), success)
mstore(0x40c0, 0x0af03baa553c3f2eaae8b2c40c9c938f32237eac9929d04798256f5f46cbf0c3)
                    mstore(0x40e0, 0x2165258937770df656fe1b7cdfa4fd77be3cfaae27f4a98f7176184100ecdbb3)
mstore(0x4100, mload(0x37a0))
success := and(eq(staticcall(gas(), 0x7, 0x40c0, 0x60, 0x40c0, 0x40), 1), success)
mstore(0x4120, mload(0x4040))
                    mstore(0x4140, mload(0x4060))
mstore(0x4160, mload(0x40c0))
                    mstore(0x4180, mload(0x40e0))
success := and(eq(staticcall(gas(), 0x6, 0x4120, 0x80, 0x4120, 0x40), 1), success)
mstore(0x41a0, 0x04dd631b478e6e20365682eec704759b8d6078732d2f7e207655a4a14c973e33)
                    mstore(0x41c0, 0x13f046f6142cb9e899c3c5408c34800e173e5690242b2221b956e148b8f9fe69)
mstore(0x41e0, mload(0x37c0))
success := and(eq(staticcall(gas(), 0x7, 0x41a0, 0x60, 0x41a0, 0x40), 1), success)
mstore(0x4200, mload(0x4120))
                    mstore(0x4220, mload(0x4140))
mstore(0x4240, mload(0x41a0))
                    mstore(0x4260, mload(0x41c0))
success := and(eq(staticcall(gas(), 0x6, 0x4200, 0x80, 0x4200, 0x40), 1), success)
mstore(0x4280, 0x2b4028c4b4137f4962ea809c4c68df73dfc531733455d74200b2eea4c896fdf9)
                    mstore(0x42a0, 0x09e23e4b1af881b7543a55eb52ddb34dbfc2b17bbd14d70b52d60cbece4593b0)
mstore(0x42c0, mload(0x37e0))
success := and(eq(staticcall(gas(), 0x7, 0x4280, 0x60, 0x4280, 0x40), 1), success)
mstore(0x42e0, mload(0x4200))
                    mstore(0x4300, mload(0x4220))
mstore(0x4320, mload(0x4280))
                    mstore(0x4340, mload(0x42a0))
success := and(eq(staticcall(gas(), 0x6, 0x42e0, 0x80, 0x42e0, 0x40), 1), success)
mstore(0x4360, 0x0b878f85a4ce6afee977453119252115899c9c75efe17874cf976bc9de00481c)
                    mstore(0x4380, 0x15d12647db013b76ed4c193f99bf2f24d7eb0219ab1017abfc6889c03553f19c)
mstore(0x43a0, mload(0x3800))
success := and(eq(staticcall(gas(), 0x7, 0x4360, 0x60, 0x4360, 0x40), 1), success)
mstore(0x43c0, mload(0x42e0))
                    mstore(0x43e0, mload(0x4300))
mstore(0x4400, mload(0x4360))
                    mstore(0x4420, mload(0x4380))
success := and(eq(staticcall(gas(), 0x6, 0x43c0, 0x80, 0x43c0, 0x40), 1), success)
mstore(0x4440, 0x304afd4515c4223fe009b5fa90e02284b29d5ba990f59989764603fe0e333a32)
                    mstore(0x4460, 0x216b57773ce2b3907f530aa8c2e0394f347cfe5523108ffa83c155ce2eca6eb4)
mstore(0x4480, mload(0x3820))
success := and(eq(staticcall(gas(), 0x7, 0x4440, 0x60, 0x4440, 0x40), 1), success)
mstore(0x44a0, mload(0x43c0))
                    mstore(0x44c0, mload(0x43e0))
mstore(0x44e0, mload(0x4440))
                    mstore(0x4500, mload(0x4460))
success := and(eq(staticcall(gas(), 0x6, 0x44a0, 0x80, 0x44a0, 0x40), 1), success)
mstore(0x4520, 0x210e1970568c35d10a8eb878b5f9a2c846c0066938254f2cd37c09a0bbd008a2)
                    mstore(0x4540, 0x2996e8356b8978a88da0c73052447baa696783ff1e4220c135561f7c8f330fd9)
mstore(0x4560, mload(0x3840))
success := and(eq(staticcall(gas(), 0x7, 0x4520, 0x60, 0x4520, 0x40), 1), success)
mstore(0x4580, mload(0x44a0))
                    mstore(0x45a0, mload(0x44c0))
mstore(0x45c0, mload(0x4520))
                    mstore(0x45e0, mload(0x4540))
success := and(eq(staticcall(gas(), 0x6, 0x4580, 0x80, 0x4580, 0x40), 1), success)
mstore(0x4600, 0x10e7177a1087a26e4cfe8698b7c297044c0cc10653fd006b0c252f823c260802)
                    mstore(0x4620, 0x2b0d490a9269fc18aec76e578f2bfd1e393a0b67d83947a42bd3fe36f354cd6f)
mstore(0x4640, mload(0x3860))
success := and(eq(staticcall(gas(), 0x7, 0x4600, 0x60, 0x4600, 0x40), 1), success)
mstore(0x4660, mload(0x4580))
                    mstore(0x4680, mload(0x45a0))
mstore(0x46a0, mload(0x4600))
                    mstore(0x46c0, mload(0x4620))
success := and(eq(staticcall(gas(), 0x6, 0x4660, 0x80, 0x4660, 0x40), 1), success)
mstore(0x46e0, 0x106b01c02c9892f86dc3ad2cf7e3d42e74a928d2c40f05ceab268f6badca5db0)
                    mstore(0x4700, 0x1d3ed3b9f9891fa085dceadb24b4564f3faecfcdd8376a4b67566a23c53b9747)
mstore(0x4720, mload(0x3880))
success := and(eq(staticcall(gas(), 0x7, 0x46e0, 0x60, 0x46e0, 0x40), 1), success)
mstore(0x4740, mload(0x4660))
                    mstore(0x4760, mload(0x4680))
mstore(0x4780, mload(0x46e0))
                    mstore(0x47a0, mload(0x4700))
success := and(eq(staticcall(gas(), 0x6, 0x4740, 0x80, 0x4740, 0x40), 1), success)
mstore(0x47c0, mload(0x460))
                    mstore(0x47e0, mload(0x480))
mstore(0x4800, mload(0x38a0))
success := and(eq(staticcall(gas(), 0x7, 0x47c0, 0x60, 0x47c0, 0x40), 1), success)
mstore(0x4820, mload(0x4740))
                    mstore(0x4840, mload(0x4760))
mstore(0x4860, mload(0x47c0))
                    mstore(0x4880, mload(0x47e0))
success := and(eq(staticcall(gas(), 0x6, 0x4820, 0x80, 0x4820, 0x40), 1), success)
mstore(0x48a0, mload(0x4a0))
                    mstore(0x48c0, mload(0x4c0))
mstore(0x48e0, mload(0x38c0))
success := and(eq(staticcall(gas(), 0x7, 0x48a0, 0x60, 0x48a0, 0x40), 1), success)
mstore(0x4900, mload(0x4820))
                    mstore(0x4920, mload(0x4840))
mstore(0x4940, mload(0x48a0))
                    mstore(0x4960, mload(0x48c0))
success := and(eq(staticcall(gas(), 0x6, 0x4900, 0x80, 0x4900, 0x40), 1), success)
mstore(0x4980, mload(0x4e0))
                    mstore(0x49a0, mload(0x500))
mstore(0x49c0, mload(0x38e0))
success := and(eq(staticcall(gas(), 0x7, 0x4980, 0x60, 0x4980, 0x40), 1), success)
mstore(0x49e0, mload(0x4900))
                    mstore(0x4a00, mload(0x4920))
mstore(0x4a20, mload(0x4980))
                    mstore(0x4a40, mload(0x49a0))
success := and(eq(staticcall(gas(), 0x6, 0x49e0, 0x80, 0x49e0, 0x40), 1), success)
mstore(0x4a60, mload(0x3c0))
                    mstore(0x4a80, mload(0x3e0))
mstore(0x4aa0, mload(0x3900))
success := and(eq(staticcall(gas(), 0x7, 0x4a60, 0x60, 0x4a60, 0x40), 1), success)
mstore(0x4ac0, mload(0x49e0))
                    mstore(0x4ae0, mload(0x4a00))
mstore(0x4b00, mload(0x4a60))
                    mstore(0x4b20, mload(0x4a80))
success := and(eq(staticcall(gas(), 0x6, 0x4ac0, 0x80, 0x4ac0, 0x40), 1), success)
mstore(0x4b40, mload(0x300))
                    mstore(0x4b60, mload(0x320))
mstore(0x4b80, mload(0x3a00))
success := and(eq(staticcall(gas(), 0x7, 0x4b40, 0x60, 0x4b40, 0x40), 1), success)
mstore(0x4ba0, mload(0x4ac0))
                    mstore(0x4bc0, mload(0x4ae0))
mstore(0x4be0, mload(0x4b40))
                    mstore(0x4c00, mload(0x4b60))
success := and(eq(staticcall(gas(), 0x6, 0x4ba0, 0x80, 0x4ba0, 0x40), 1), success)
mstore(0x4c20, mload(0x340))
                    mstore(0x4c40, mload(0x360))
mstore(0x4c60, mload(0x3ba0))
success := and(eq(staticcall(gas(), 0x7, 0x4c20, 0x60, 0x4c20, 0x40), 1), success)
mstore(0x4c80, mload(0x4ba0))
                    mstore(0x4ca0, mload(0x4bc0))
mstore(0x4cc0, mload(0x4c20))
                    mstore(0x4ce0, mload(0x4c40))
success := and(eq(staticcall(gas(), 0x6, 0x4c80, 0x80, 0x4c80, 0x40), 1), success)
mstore(0x4d00, mload(0x380))
                    mstore(0x4d20, mload(0x3a0))
mstore(0x4d40, mload(0x3bc0))
success := and(eq(staticcall(gas(), 0x7, 0x4d00, 0x60, 0x4d00, 0x40), 1), success)
mstore(0x4d60, mload(0x4c80))
                    mstore(0x4d80, mload(0x4ca0))
mstore(0x4da0, mload(0x4d00))
                    mstore(0x4dc0, mload(0x4d20))
success := and(eq(staticcall(gas(), 0x6, 0x4d60, 0x80, 0x4d60, 0x40), 1), success)
mstore(0x4de0, mload(0x1c0))
                    mstore(0x4e00, mload(0x1e0))
mstore(0x4e20, mload(0x3cc0))
success := and(eq(staticcall(gas(), 0x7, 0x4de0, 0x60, 0x4de0, 0x40), 1), success)
mstore(0x4e40, mload(0x4d60))
                    mstore(0x4e60, mload(0x4d80))
mstore(0x4e80, mload(0x4de0))
                    mstore(0x4ea0, mload(0x4e00))
success := and(eq(staticcall(gas(), 0x6, 0x4e40, 0x80, 0x4e40, 0x40), 1), success)
mstore(0x4ec0, mload(0x9c0))
                    mstore(0x4ee0, mload(0x9e0))
mstore(0x4f00, sub(f_q, mload(0x3d00)))
success := and(eq(staticcall(gas(), 0x7, 0x4ec0, 0x60, 0x4ec0, 0x40), 1), success)
mstore(0x4f20, mload(0x4e40))
                    mstore(0x4f40, mload(0x4e60))
mstore(0x4f60, mload(0x4ec0))
                    mstore(0x4f80, mload(0x4ee0))
success := and(eq(staticcall(gas(), 0x6, 0x4f20, 0x80, 0x4f20, 0x40), 1), success)
mstore(0x4fa0, mload(0xa60))
                    mstore(0x4fc0, mload(0xa80))
mstore(0x4fe0, mload(0x3d20))
success := and(eq(staticcall(gas(), 0x7, 0x4fa0, 0x60, 0x4fa0, 0x40), 1), success)
mstore(0x5000, mload(0x4f20))
                    mstore(0x5020, mload(0x4f40))
mstore(0x5040, mload(0x4fa0))
                    mstore(0x5060, mload(0x4fc0))
success := and(eq(staticcall(gas(), 0x6, 0x5000, 0x80, 0x5000, 0x40), 1), success)
mstore(0x5080, mload(0x5000))
                    mstore(0x50a0, mload(0x5020))
mstore(0x50c0, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2)
            mstore(0x50e0, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed)
            mstore(0x5100, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b)
            mstore(0x5120, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa)
mstore(0x5140, mload(0xa60))
                    mstore(0x5160, mload(0xa80))
mstore(0x5180, 0x05ec07eba193b9d1e52c9fc40d4c55272b5d65ade83bddf38816c4e8e29145b4)
            mstore(0x51a0, 0x132535d20a504b0545984fd60c339fe5d1823fd1a5a6924c092e6e343f56581d)
            mstore(0x51c0, 0x2bc9c67ed9417eaa546deaaa57c6a8f725cdd7344b86bd1b0f694e12444a93c7)
            mstore(0x51e0, 0x2e32dca114ebdfcee8c297e6c0cc78fd77e3bb4c22c5f484b80c32be6e1aa93c)
success := and(eq(staticcall(gas(), 0x8, 0x5080, 0x180, 0x5080, 0x20), 1), success)
success := and(eq(mload(0x5080), 1), success)

            // Revert if anything fails
            if iszero(success) { revert(0, 0) }

            // Return empty bytes on success
            return(0, 0)

        }
    }
}
        