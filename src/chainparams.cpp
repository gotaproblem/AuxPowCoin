// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "arith_uint256.h"
#include "crypto/scrypt.h"
#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    //txNew.vin[0].scriptSig = CScript() << 0x1d00ffff << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vin[0].scriptSig = CScript() << 0x1e0ffff0 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);



                // If genesis block hash does not match, then generate new genesis hash.
        if (false)// && genesis.GetHash() != uint256S("0x64d888bd4f6174255de3f6d87212738b68dae718b2e96260178bb04c64a184cf"))
        {
            printf("Searching for genesis block...\n");
            // This will figure out a valid hash and Nonce if you're
            // creating a different genesis block:
            arith_uint256 hashTarget = arith_uint256().SetCompact(genesis.nBits);//.getuint256();
            arith_uint256 thash;
            char scratchpad[SCRYPT_SCRATCHPAD_SIZE];

            printf("nBits = %08x\n", genesis.nBits);
            printf("target = %s\n", hashTarget.ToString().c_str());
            printf("MerkleRoot = %s\n", genesis.hashMerkleRoot.ToString().c_str());

            while ( true )
            {
                // Detect SSE2: 32bit x86 Linux or Windows
                scrypt_1024_1_1_256_sp(BEGIN(genesis.nVersion), BEGIN(thash), scratchpad);

                if (thash <= hashTarget)
                    break;
                if ((genesis.nNonce & 0xFFF) == 0)
                {
                    printf("nonce %08X: hash = %s\n", genesis.nNonce, thash.ToString().c_str());
                }
                ++genesis.nNonce;
                if (genesis.nNonce == 0)
                {
                    printf("NONCE WRAPPED, incrementing time\n");
                    ++genesis.nTime;
                }
            }
            printf ("\n");
            //printf("thash = %s (target = %s)\n", thash.ToString().c_str(), hashTarget.ToString().c_str());
            printf("block.nTime = %u \n", genesis.nTime);
            printf("block.nNonce = %u \n", genesis.nNonce);
            printf("block.GetHash = %s\n\n", genesis.GetHash().ToString().c_str());
        }


    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=12a765e31ffd40, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=97ddfb, nTime=1317972665, nBits=1e0ffff0, nNonce=2084524493, vtx=1)
 *   CTransaction(hash=97ddfb, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104404e592054696d65732030352f4f63742f32303131205374657665204a6f62732c204170706c65e280997320566973696f6e6172792c2044696573206174203536)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x040184710FA689AD502369)
 *   vMerkleTree: 97ddfb
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Mimble Wimble lol";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.BIP34Height = 2;
        consensus.BIP34Hash = uint256S("0x1dcbed4c39397993c434cc49e51af50d775df85aeb17c1dec332ba1820a8c1a0");
        consensus.BIP65Height = 2;                                                      // 74658d61423c04a82d8853ea7ba80dbea0b05515b5c699de82ce7adb3894b0bd
        consensus.BIP66Height = 2;                                                      // 74658d61423c04a82d8853ea7ba80dbea0b05515b5c699de82ce7adb3894b0bd
        //consensus.powLimit = uint256S("0x0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit = uint256S("0x00000ffff0000000000000000000000000000000000000000000000000000000");
        //consensus.powLimit = uint256S("0x0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 24 * 60 * 60;                                    // 1 day
        //consensus.nClassicPowTargetTimespan = 12 * 60 * 60;                           // twelve hours
        consensus.nPowTargetSpacing = 30;						                        /* 30 second blocks */
        consensus.fPowAllowMinDifficultyBlocks = false;			                        /* this is mainnet */
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 2736;                                // 95% of 2880
        consensus.nMinerConfirmationWindow = 2880;                                      // nPowTargetTimespan / nPowTargetSpacing
        
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601;// January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999;  // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1541030400;      // November 1st, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1572566400;        // November 1st, 2019

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1563580800;   // July 20th, 2019.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1595203200;     // July 20th, 2020.

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000100010001");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x230cdec4c3c064f886569e9ad6d7561f43e47754ba13b17247ba61b47f53f8c1"); //2432033
		
		/* AuxPow rules */
		consensus.nAuxpowChainId        = 0x05b3;		                               /* Mincoin CoinMarketCap ranking on Genesis date */
        consensus.nAuxpowStartHeight    = 1000;
        consensus.fStrictChainId        = true;
        consensus.nLegacyBlocksBefore   = 1000;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x60;												      /* ` */
        pchMessageStart[1] = 0x5e;												      /* ^ */
        pchMessageStart[2] = 0x5d;												      /* ] */
        pchMessageStart[3] = 0x5c;												      /* \ */

        nDefaultPort       = 9901;
        nPruneAfterHeight  = 100000;

        //arith_uint256 tmp = arith_uint256()
        //printf("min nBit: %08x\n", (arith_uint256)consensus.powLimit.GetCompact());

		/* 17th September 2019 @ 07:11:17 */
        //genesis = CreateGenesisBlock(1568704277, 88864, 0x1e0ffff0, 1, 10000 * COIN );
		genesis = CreateGenesisBlock(1568704277, 230360, 0x1e0ffff0, 1, 10000 * COIN );
		//genesis = CreateGenesisBlock(1568704277, 0, 0x1d00ffff, 1, 10000 * COIN );

        consensus.hashGenesisBlock = genesis.GetHash();
       
        //unsigned char *ptr = (unsigned char*)&consensus.hashGenesisBlock;
        //for ( int i = 31; i >= 0; i-- ) {
		//	printf ( "%02x", *(ptr + i) );	/* reverse bytes */
        //}
        //printf ( "\n" );

        assert(consensus.hashGenesisBlock == uint256S("84d2ba64f774aa6305a01d45bca7435cd44875a16081bc4f5dcc3b82305ceadb"));
        assert(genesis.hashMerkleRoot == uint256S("d769580b9f996e38c0ada9d792d46526f87b46e6dc82bb8fb3449af9a8ed5eef"));

        

		vFixedSeeds.clear();
        vSeeds.clear();


        // Note that of those with the service bits flag, most only support a subset of possible options
        //vSeeds.push_back(CDNSSeedData("apcointools.com", "seed.apcointools.com", true)); 
        //vSeeds.push_back(CDNSSeedData("apcoinpool.org", "seed.apcoinpool.org", true)); 
        //vSeeds.push_back(CDNSSeedData("192.168.0.169", "192.168.0.169", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,23);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,151);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        //vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers        = true;
        fDefaultConsistencyChecks   = false;
        fRequireStandard            = true;
        fMineBlocksOnDemand         = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("84d2ba64f774aa6305a01d45bca7435cd44875a16081bc4f5dcc3b82305ceadb"))
            //( 234665, uint256S("0xfba8afe9fc734e146a2273cb956d2c30c7a86832007ded99d6b5fd2637d718e3"))
            //(1438440, uint256S("0xfdb38e23fda036ef965f270285d9a6dd2ce8a05d7c2f3dcd5323d9c834d14799"))
            //(2029907, uint256S("0x67fa9341f35b8bf1170780322bc977cecf946b703021bd2366984b83831dbb82"))
            //(2432033, uint256S("0x230cdec4c3c064f886569e9ad6d7561f43e47754ba13b17247ba61b47f53f8c1"))
        };

        chainTxData = {};/*ChainTxData{
            // Data as of block 230cdec4c3c064f886569e9ad6d7561f43e47754ba13b17247ba61b47f53f8c1 (height 2432033).
            1567704025, // * UNIX timestamp of last known number of transactions
            2900203,    // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            .15         // * estimated number of transactions per second after that timestamp
        };*/
    }
};
static CMainParams mainParams;

/**
 * Testnet (v4)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        //consensus.BIP34Height = 751;
        //consensus.BIP34Hash = uint256S("0xba178015425b75c85985a89f162a02f96cbd5bbb91c8b1415e9368d369eb7948");
        //consensus.BIP65Height = 751; // ba178015425b75c85985a89f162a02f96cbd5bbb91c8b1415e9368d369eb7948
        //consensus.BIP66Height = 751; // ba178015425b75c85985a89f162a02f96cbd5bbb91c8b1415e9368d369eb7948
        //consensus.powLimit = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit = uint256S("0000ffff00000000000000000000000000000000000000000000000000000000");
        consensus.nPowTargetTimespan = 60 * 60; // sixty minutes
        consensus.nClassicPowTargetTimespan = 12 * 60 * 60; // twelve hours
        consensus.nPowTargetSpacing = 30;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.nMinDifficultySince = 1394838000; // 15 Mar 2014
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 2160; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2880; // 336 * nPowTargetTimespan / nPowTargetSpacing
        //consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        //consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        //consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        //consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        //consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1550577517; // February 19th, 2019
        //consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1582113517; // February 19th, 2020

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        //consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        //consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1550577517; // February 19th 2019
        //consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1582113517; // February 19th 2020

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000000292c5adfe5");

        // By default assume that the signatures in ancestors of this block are valid.
        //consensus.defaultAssumeValid = uint256S("0x3108d2d8ce7993ee31c01b1c60b133ed44b7fb768e1709b4e7bf551606665671"); //129907

        pchMessageStart[0] = 113;
        pchMessageStart[1] = 96;
        pchMessageStart[2] = 65;
        pchMessageStart[3] = 247;
        nDefaultPort = 19901;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1568704277, 171262, 0x1f00ffff, 1, 10000 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("37c043f31b196da9c4ff5ad7928416d698ccbbe5215fd35e090aab736521cae1"));
        assert(genesis.hashMerkleRoot == uint256S("d769580b9f996e38c0ada9d792d46526f87b46e6dc82bb8fb3449af9a8ed5eef"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        //vSeeds.push_back(CDNSSeedData("apcointools.com", "testnet-seed.apcointools.com", true));
        //vSeeds.push_back(CDNSSeedData("apcoinpool.org", "testnet-seed.apcoinpool.org", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        //vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("37c043f31b196da9c4ff5ad7928416d698ccbbe5215fd35e090aab736521cae1"))
            //( 129907, uint256S("3108d2d8ce7993ee31c01b1c60b133ed44b7fb768e1709b4e7bf551606665671"))
        };

        chainTxData = {};/*ChainTxData{
            // Data as of block 3108d2d8ce7993ee31c01b1c60b133ed44b7fb768e1709b4e7bf551606665671 (height 129907)
            1567706478,
            130082,
            0.03
        };*/

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        //consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        //consensus.BIP34Hash = uint256();
        //consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        //consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        //consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit = uint256S("7fffff0000000000000000000000000000000000000000000000000000000000");
        consensus.nPowTargetTimespan = 60 * 60; // sixty minutes
        consensus.nClassicPowTargetTimespan = 12 * 60 * 60; // twelve hours
        consensus.nPowTargetSpacing = 30;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.nMinDifficultySince = 0;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        //consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        //consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        //consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        //consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        //consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        //consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        //consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        //consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        //consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 110;
        pchMessageStart[1] = 13;
        pchMessageStart[2] = 209;
        pchMessageStart[3] = 202;
        nDefaultPort = 19903;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1568704277, 0, 0x207fffff, 1, 100 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("dc8d86a65252cdf5547968681df8f211c7649133e5287c76a93103cdd8a92137"));
        assert(genesis.hashMerkleRoot == uint256S("b7f872afd1186ff424ec98bf5da08188ea66a13b5448f8412e440b870df474ac"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("dc8d86a65252cdf5547968681df8f211c7649133e5287c76a93103cdd8a92137"))
            //( 0, uint256S("b36dc7d31a3c0cda11b1ddbbb50263e2eca2a52c319b9e02c9a34452194289b3"))
        };

        chainTxData = {};/*ChainTxData{
            0,
            0,
            0
        };*/

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
 
