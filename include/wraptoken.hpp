#pragma once

#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>
#include <eosio/singleton.hpp>

#include <string>

#include <bridge.hpp>
#include <eosio.token.hpp>

namespace eosiosystem {
   class system_contract;
}

namespace eosio {

   using std::string;

   class [[eosio::contract("wraptoken")]] wraptoken : public contract {
      private:

         // for bridge communication
         TABLE lpstruct {

            uint64_t id;

            bridge::lightproof lp;

            uint64_t primary_key()const { return id; }

            EOSLIB_SERIALIZE( lpstruct, (id)(lp) )

         } _light_proof_obj;

         TABLE hpstruct {

            uint64_t id;

            bridge::heavyproof hp;

            uint64_t primary_key()const { return id; }

            EOSLIB_SERIALIZE( hpstruct, (id)(hp) )

         } _heavy_proof_obj;

         using lptable = eosio::singleton<"lightproof"_n, lpstruct>;
         using hptable = eosio::singleton<"heavyproof"_n, hpstruct>;

         lptable _light_proof;
         hptable _heavy_proof;


         // structure used for globals - see `init` action for documentation
         struct [[eosio::table]] global {
            checksum256   chain_id;
            name          bridge_contract;
            checksum256   paired_chain_id;
            name          paired_wraplock_contract;
            name          paired_token_contract;
         } globalrow;

         // structure for keeping user balances, scoped by user
         struct [[eosio::table]] account {
            asset    balance;

            uint64_t primary_key()const { return balance.symbol.code().raw(); }
         };

         // structure for token stats and wallet compatibility
         struct [[eosio::table]] currency_stats {

            asset         supply;
            asset         max_supply;
            name          issuer;

            uint64_t primary_key()const { return supply.symbol.code().raw(); }
         };

         // structure used for retaining action receipt digests of accepted proven actions, to prevent replay attacks
         struct [[eosio::table]] processed {

           uint64_t                        id;
           checksum256                     receipt_digest;

           uint64_t primary_key()const { return id; }
           checksum256 by_digest()const { return receipt_digest; }

           EOSLIB_SERIALIZE( processed, (id)(receipt_digest))

         };

         void add_or_assert(const bridge::actionproof& actionproof, const name& payer);
         void sub_balance( const name& owner, const asset& value );
         void add_balance( const name& owner, const asset& value, const name& ram_payer );
         void _issue(const name& prover, const bridge::actionproof actionproof);
         void _cancel(const name& prover, const bridge::actionproof actionproof);

      public:
         using contract::contract;

         // structure used for the `emitxfer` action used in proof on native token chain
         struct [[eosio::table]] xfer {
           name             owner;
           extended_asset   quantity;
           name             beneficiary;
         };


         /**
          * Allows contract account to set which chains and associated contracts are used for all interchain transfers.
          *
          * @param chain_id - the id of the chain running this contract
          * @param bridge_contract - the bridge contract on this chain
          * @param paired_chain_id - the id of the chain hosting the native tokens
          * @param paired_wraplock_contract - the wraplock contract on the native token chain
          * @param paired_token_contract - the token contract on the native chain being enabled for interchain transfers
          */
         [[eosio::action]]
         void init(const checksum256& chain_id, const name& bridge_contract, const checksum256& paired_chain_id, const name& paired_wraplock_contract, const name& paired_token_contract);

         /**
          * Allows `prover` account to issue wrapped tokens and send them to the beneficiary indentified in the `actionproof`.
          *
          * @param prover - the calling account whose ram is used for storing the action receipt digest to prevent replay attacks
          * @param blockproof - the heavy proof data structure
          * @param actionproof - the proof structure for the `emitxfer` action associated with the locking transfer action on the native chain
          */
         [[eosio::action]]
         void issuea(const name& prover, const bridge::heavyproof blockproof, const bridge::actionproof actionproof);

         /**
          * Allows `prover` account to issue wrapped tokens and send them to the beneficiary indentified in the `actionproof`.
          *
          * @param prover - the calling account whose ram is used for storing the action receipt digest to prevent replay attacks
          * @param blockproof - the light proof data structure
          * @param actionproof - the proof structure for the `emitxfer` action associated with the locking transfer action on the native chain
          */
         [[eosio::action]]
         void issueb(const name& prover, const bridge::lightproof blockproof, const bridge::actionproof actionproof);

         /**
          * Allows `prover` account to cancel a token transfer and return them to the beneficiary indentified in the `actionproof`.
          *
          * @param prover - the calling account whose ram is used for storing the action receipt digest to prevent replay attacks
          * @param blockproof - the heavy proof data structure
          * @param actionproof - the proof structure for the `emitxfer` action associated with the locking transfer action on the native chain
          */
         [[eosio::action]]
         void cancela(const name& prover, const bridge::heavyproof blockproof, const bridge::actionproof actionproof);

         /**
          * Allows `prover` account to cancel a token transfer and return them to the beneficiary indentified in the `actionproof`.
          *
          * @param prover - the calling account whose ram is used for storing the action receipt digest to prevent replay attacks
          * @param blockproof - the light proof data structure
          * @param actionproof - the proof structure for the `emitxfer` action associated with the locking transfer action on the native chain
          */
         [[eosio::action]]
         void cancelb(const name& prover, const bridge::lightproof blockproof, const bridge::actionproof actionproof);

         /**
          * Allows `owner` account to retire the `quantity` of wrapped tokens and calls the `emitxfer` action inline so that can be used
          * as the basis for a proof of locking for the withdraw actions on the native chain.
          *
          * @param from - the owner of the tokens to be sent to the native token chain
          * @param to - this contract account
          * @param quantity - the asset to be sent to the native token chain
          * @param memo - the beneficiary account on the native token chain
          */
         [[eosio::action]]
         void retire(const name& owner,  const asset& quantity, const name& beneficiary);


         [[eosio::action]]
         void transfer( const name&    from,
                        const name&    to,
                        const asset&   quantity,
                        const string&  memo );
  
         [[eosio::action]]
         void open( const name& owner, const symbol& symbol, const name& ram_payer );


         [[eosio::action]]
         void close( const name& owner, const symbol& symbol );

         [[eosio::action]]
         void emitxfer(const wraptoken::xfer& xfer);

         [[eosio::action]]
         void clear(const name& caller, const std::vector<name> user_accounts, const std::vector<symbol> symbols);

         static asset get_supply( const name& token_contract_account, const symbol_code& sym_code )
         {
            stats statstable( token_contract_account, sym_code.raw() );
            const auto& st = statstable.get( sym_code.raw() );
            return st.supply;
         }

         static asset get_balance( const name& token_contract_account, const name& owner, const symbol_code& sym_code )
         {
            accounts accountstable( token_contract_account, owner.value );
            const auto& ac = accountstable.get( sym_code.raw() );
            return ac.balance;
         }

         using transfer_action = action_wrapper<"transfer"_n, &token::transfer>;
         using heavyproof_action = action_wrapper<"checkproofb"_n, &bridge::checkproofb>;
         using lightproof_action = action_wrapper<"checkproofc"_n, &bridge::checkproofc>;
         using emitxfer_action = action_wrapper<"emitxfer"_n, &wraptoken::emitxfer>;

         typedef eosio::multi_index< "accounts"_n, account > accounts;
         typedef eosio::multi_index< "stat"_n, currency_stats > stats;

      
         typedef eosio::multi_index< "processed"_n, processed,
            indexed_by<"digest"_n, const_mem_fun<processed, checksum256, &processed::by_digest>>> processedtable;

         using globaltable = eosio::singleton<"global"_n, global>;

         globaltable global_config;

         processedtable _processedtable;

         wraptoken( name receiver, name code, datastream<const char*> ds ) :
         contract(receiver, code, ds),
         global_config(_self, _self.value),
         _processedtable(_self, _self.value),
         _light_proof(receiver, receiver.value),
         _heavy_proof(receiver, receiver.value)
         {

         }
        
   };

}

