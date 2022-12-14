#include <wraptoken.hpp>

namespace eosio {


//adds a proof to the list of processed proofs (throws an exception if proof already exists)
void wraptoken::add_or_assert(const bridge::actionproof& actionproof, const name& payer){

    auto pid_index = _processedtable.get_index<"digest"_n>();

    std::vector<char> serializedAction = pack(actionproof.action);
    std::vector<char> serializedReceipt = pack(actionproof.receipt);
    checksum256 action_digest = sha256(serializedAction.data(), serializedAction.size());
    checksum256 action_receipt_digest = sha256(serializedReceipt.data(), serializedReceipt.size());

    auto p_itr = pid_index.find(action_receipt_digest);

    check(p_itr == pid_index.end(), "action already proved");

    _processedtable.emplace( payer, [&]( auto& s ) {
        s.id = _processedtable.available_primary_key();
        s.receipt_digest = action_receipt_digest;
    });

}

void wraptoken::init(const checksum256& chain_id, const name& bridge_contract, const checksum256& paired_chain_id, const name& paired_wraplock_contract, const name& paired_token_contract)
{
    check(!global_config.exists(), "contract already initialized");

    require_auth( _self );

    check( is_account( bridge_contract ), "bridge_contract account does not exist" );

    auto global = global_config.get_or_create(_self, globalrow);
    global.chain_id = chain_id;
    global.bridge_contract = bridge_contract;
    global.paired_chain_id = paired_chain_id;
    global.paired_wraplock_contract = paired_wraplock_contract;
    global.paired_token_contract = paired_token_contract;
    global.enabled = true;
    global_config.set(global, _self);

}

void wraptoken::_issue(const name& prover, const bridge::actionproof actionproof)
{
    auto global = global_config.get();

    wraptoken::xfer lock_act = unpack<wraptoken::xfer>(actionproof.action.data);

    check(actionproof.action.account == global.paired_wraplock_contract, "proof account does not match paired wraplock account");

    add_or_assert(actionproof, prover);

    auto sym = lock_act.quantity.quantity.symbol;
    check( sym.is_valid(), "invalid symbol name" );
    //check( memo.size() <= 256, "memo has more than 256 bytes" );

    stats statstable( get_self(), sym.code().raw() );
    auto existing = statstable.find( sym.code().raw() );

    // create if no existing matching symbol exists
    if (existing == statstable.end()) {
        statstable.emplace( get_self(), [&]( auto& s ) {
           s.supply = asset(0, sym);
           s.max_supply = asset((1LL<<62)-1, sym);
           s.issuer = get_self();
        });
        existing = statstable.find( sym.code().raw() );
    }
    
    check( existing != statstable.end(), "token with symbol does not exist, create token before issue" );

    check(actionproof.action.name == "emitxfer"_n, "must provide proof of token locking before issuing");

    const auto& st = *existing;

    check( lock_act.quantity.quantity.is_valid(), "invalid quantity" );
    check( lock_act.quantity.quantity.amount > 0, "must issue positive quantity" );

    check( lock_act.quantity.quantity.symbol == st.supply.symbol, "symbol precision mismatch" );
    check( lock_act.quantity.quantity.amount <= st.max_supply.amount - st.supply.amount, "quantity exceeds available supply");

    statstable.modify( st, same_payer, [&]( auto& s ) {
       s.supply += lock_act.quantity.quantity;
    });

    add_balance( _self, lock_act.quantity.quantity, _self );

    // ensure beneficiary has a balance
    add_balance( lock_act.beneficiary, asset(0, lock_act.quantity.quantity.symbol), prover );

    // transfer to beneficiary
    wraptoken::transfer_action act(_self, permission_level{_self, "active"_n});
    act.send(_self, lock_act.beneficiary, lock_act.quantity.quantity, std::string("") );
    
}

// mints the wrapped token, requires heavy block proof and action proof
void wraptoken::issuea(const name& prover, const bridge::heavyproof blockproof, const bridge::actionproof actionproof)
{
    require_auth(prover);

    check(global_config.exists(), "contract must be initialized first");
    auto global = global_config.get();

    check(global.enabled == true, "contract has been disabled");

    check(blockproof.chain_id == global.paired_chain_id, "proof chain does not match paired chain");

    // check proof against bridge
    // will fail tx if prove is invalid
    auto p = _heavy_proof.get_or_create(_self, _heavy_proof_obj);
    p.hp = blockproof;
    _heavy_proof.set(p, _self);
    wraptoken::heavyproof_action checkproof_act(global.bridge_contract, permission_level{_self, "active"_n});
    checkproof_act.send(_self, actionproof);

    _issue(prover, actionproof);
}

// mints the wrapped token, requires light block proof and action proof
void wraptoken::issueb(const name& prover, const bridge::lightproof blockproof, const bridge::actionproof actionproof)
{
    require_auth(prover);

    check(global_config.exists(), "contract must be initialized first");
    auto global = global_config.get();

    check(global.enabled == true, "contract has been disabled");

    check(blockproof.chain_id == global.paired_chain_id, "proof chain does not match paired chain");

    // check proof against bridge
    // will fail tx if prove is invalid
    auto p = _light_proof.get_or_create(_self, _light_proof_obj);
    p.lp = blockproof;
    _light_proof.set(p, _self);
    wraptoken::lightproof_action checkproof_act(global.bridge_contract, permission_level{_self, "active"_n});
    checkproof_act.send(_self, actionproof);

    _issue(prover, actionproof);
}

void wraptoken::_cancel(const name& prover, const bridge::actionproof actionproof)
{
    auto global = global_config.get();

    wraptoken::xfer lock_act = unpack<wraptoken::xfer>(actionproof.action.data);

    check(actionproof.action.account == global.paired_wraplock_contract, "proof account does not match paired wraplock account");

    add_or_assert(actionproof, prover);

    auto sym = lock_act.quantity.quantity.symbol;
    check( sym.is_valid(), "invalid symbol name" );
    //check( memo.size() <= 256, "memo has more than 256 bytes" );

    check(actionproof.action.name == "emitxfer"_n, "must provide proof of token locking before issuing");

    check( lock_act.quantity.quantity.is_valid(), "invalid quantity" );
    check( lock_act.quantity.quantity.amount > 0, "must issue positive quantity" );

    wraptoken::xfer x = {
      .owner = _self, // todo - check whether this should show as lock_act.beneficiary
      .quantity = extended_asset(lock_act.quantity.quantity, global.paired_token_contract),
      .beneficiary = lock_act.owner
    };

    // return to lock_act.owner so can be withdrawn from wraplock
    wraptoken::emitxfer_action act(_self, permission_level{_self, "active"_n});
    act.send(x);

}

void wraptoken::cancela(const name& prover, const bridge::heavyproof blockproof, const bridge::actionproof actionproof)
{
    require_auth(prover);

    check(global_config.exists(), "contract must be initialized first");
    auto global = global_config.get();

    check(global.enabled == true, "contract has been disabled");

    check(blockproof.chain_id == global.paired_chain_id, "proof chain does not match paired chain");

    check(current_time_point().sec_since_epoch() > blockproof.blocktoprove.block.header.timestamp.to_time_point().sec_since_epoch() + 900, "must wait 15 minutes to cancel");

    // check proof against bridge
    // will fail tx if prove is invalid
    auto p = _heavy_proof.get_or_create(_self, _heavy_proof_obj);
    p.hp = blockproof;
    _heavy_proof.set(p, _self);
    wraptoken::heavyproof_action checkproof_act(global.bridge_contract, permission_level{_self, "active"_n});
    checkproof_act.send(_self, actionproof);

    _cancel(prover, actionproof);
}

void wraptoken::cancelb(const name& prover, const bridge::lightproof blockproof, const bridge::actionproof actionproof)
{
    require_auth(prover);

    check(global_config.exists(), "contract must be initialized first");
    auto global = global_config.get();

    check(global.enabled == true, "contract has been disabled");

    check(blockproof.chain_id == global.paired_chain_id, "proof chain does not match paired chain");

    check(current_time_point().sec_since_epoch() > blockproof.header.timestamp.to_time_point().sec_since_epoch() + 900, "must wait 15 minutes to cancel");

    // check proof against bridge
    // will fail tx if prove is invalid
    auto p = _light_proof.get_or_create(_self, _light_proof_obj);
    p.lp = blockproof;
    _light_proof.set(p, _self);
    wraptoken::lightproof_action checkproof_act(global.bridge_contract, permission_level{_self, "active"_n});
    checkproof_act.send(_self, actionproof);

    _cancel(prover, actionproof);
}

//emits an xfer receipt to serve as proof in interchain transfers
void wraptoken::emitxfer(const wraptoken::xfer& xfer){

    check(global_config.exists(), "contract must be initialized first");
 
    require_auth(_self);

}

//Disable all user actions on the contract.
void wraptoken::disable(){

    check(global_config.exists(), "contract must be initialized first");
 
    require_auth(_self);

    auto global = global_config.get();
    global.enabled = false;
    global_config.set(global, _self);

}

//Enable all user actions on the contract.
void wraptoken::enable(){

    check(global_config.exists(), "contract must be initialized first");
 
    require_auth(_self);

    auto global = global_config.get();
    global.enabled = true;
    global_config.set(global, _self);

}

void wraptoken::retire(const name& owner,  const asset& quantity, const name& beneficiary)
{
    check(global_config.exists(), "contract must be initialized first");

    require_auth( owner );

    auto global = global_config.get();

    check(global.enabled == true, "contract has been disabled");

    auto sym = quantity.symbol;
    check( sym.is_valid(), "invalid symbol name" );

    stats statstable( get_self(), sym.code().raw() );
    auto existing = statstable.find( sym.code().raw() );
    check( existing != statstable.end(), "token with symbol does not exist" );
    const auto& st = *existing;

    check( quantity.is_valid(), "invalid quantity" );
    check( quantity.amount > 0, "must retire positive quantity" );

    check( quantity.symbol == st.supply.symbol, "symbol precision mismatch" );

    statstable.modify( st, same_payer, [&]( auto& s ) {
       s.supply -= quantity;
    });

    sub_balance( owner, quantity );

    wraptoken::xfer x = {
      .owner = owner,
      .quantity = extended_asset(quantity, global.paired_token_contract),
      .beneficiary = beneficiary
    };

    wraptoken::emitxfer_action act(_self, permission_level{_self, "active"_n});
    act.send(x);

}

void wraptoken::transfer( const name&    from,
                      const name&    to,
                      const asset&   quantity,
                      const string&  memo )
{
    check(global_config.exists(), "contract must be initialized first");

    auto global = global_config.get();
    check(global.enabled == true, "contract has been disabled");

    check( from != to, "cannot transfer to self" );
    require_auth( from );
    check( is_account( to ), "to account does not exist");
    auto sym = quantity.symbol.code();
    stats statstable( get_self(), sym.raw() );
    const auto& st = statstable.get( sym.raw() );

    require_recipient( from );
    require_recipient( to );

    check( quantity.is_valid(), "invalid quantity" );
    check( quantity.amount > 0, "must transfer positive quantity" );
    check( quantity.symbol == st.supply.symbol, "symbol precision mismatch" );
    check( memo.size() <= 256, "memo has more than 256 bytes" );

    auto payer = has_auth( to ) ? to : from;

    sub_balance( from, quantity );
    add_balance( to, quantity, payer );
}

void wraptoken::sub_balance( const name& owner, const asset& value ){

   accounts from_acnts( get_self(), owner.value );

   const auto& from = from_acnts.get( value.symbol.code().raw(), "no balance object found" );
   check( from.balance.amount >= value.amount, "overdrawn balance" );

   from_acnts.modify( from, owner, [&]( auto& a ) {
         a.balance -= value;
      });
}

void wraptoken::add_balance( const name& owner, const asset& value, const name& ram_payer ){

   accounts to_acnts( get_self(), owner.value );
   auto to = to_acnts.find( value.symbol.code().raw() );
   if( to == to_acnts.end() ) {
      to_acnts.emplace( ram_payer, [&]( auto& a ){
        a.balance = value;
      });
   } else {
      to_acnts.modify( to, same_payer, [&]( auto& a ) {
        a.balance += value;
      });
   }

}

void wraptoken::open( const name& owner, const symbol& symbol, const name& ram_payer )
{
   check(global_config.exists(), "contract must be initialized first");

   auto global = global_config.get();
   check(global.enabled == true, "contract has been disabled");

   require_auth( ram_payer );

   check( is_account( owner ), "owner account does not exist" );

   auto sym_code_raw = symbol.code().raw();
   stats statstable( get_self(), sym_code_raw );
   const auto& st = statstable.get( sym_code_raw, "symbol does not exist" );
   check( st.supply.symbol == symbol, "symbol precision mismatch" );

   accounts acnts( get_self(), owner.value );
   auto it = acnts.find( sym_code_raw );
   if( it == acnts.end() ) {
      acnts.emplace( ram_payer, [&]( auto& a ){
        a.balance = asset{0, symbol};
      });
   }

}

void wraptoken::close( const name& owner, const symbol& symbol )
{
   check(global_config.exists(), "contract must be initialized first");

   auto global = global_config.get();
   check(global.enabled == true, "contract has been disabled");
    
   require_auth( owner );
   accounts acnts( get_self(), owner.value );
   auto it = acnts.find( symbol.code().raw() );
   check( it != acnts.end(), "Balance row already deleted or never existed. Action won't have any effect." );
   check( it->balance.amount == 0, "Cannot close because the balance is not zero." );
   acnts.erase( it );

}

/*void wraptoken::clear(const std::vector<name> user_accounts, const std::vector<name> symbol_names)
{ 
  check(global_config.exists(), "contract must be initialized first");

  require_auth( _self );

  if (global_config.exists()) global_config.remove();

  // remove account balances
  for (name account: user_accounts) {

    accounts a_table( get_self(), account.value);
    while (a_table.begin() != a_table.end()) {
      auto itr = a_table.end();
      itr--;
      a_table.erase(itr);
    }

  }

  // remove stats balances
  for (name symbolname: symbol_names) {

    symbol_code sc = symbol_code(symbolname.value);
    stats s_table( get_self(), sc.raw());
    while (s_table.begin() != s_table.end()) {
      auto itr = s_table.end();
      itr--;
      s_table.erase(itr);
    }

  }

  while (_processedtable.begin() != _processedtable.end()) {
    auto itr = _processedtable.end();
    itr--;
    _processedtable.erase(itr);
  }

}*/

} /// namespace eosio

