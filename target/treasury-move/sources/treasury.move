module treasury::treasury {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;

    public struct AdminCap has key, store { id: UID }

    public struct Treasury has key {
        id: UID,
        funds: Balance<SUI>,
    }

    fun init(ctx: &mut TxContext) {
        transfer::transfer(AdminCap { id: object::new(ctx) }, ctx.sender());
        transfer::share_object(Treasury { id: object::new(ctx), funds: balance::zero() });
    }

    public fun deposit(t: &mut Treasury, c: Coin<SUI>) {
        balance::join(&mut t.funds, coin::into_balance(c));
    }

    public fun withdraw(_cap: &AdminCap, t: &mut Treasury, amount: u64, ctx: &mut TxContext): Coin<SUI> {
        coin::from_balance(balance::split(&mut t.funds, amount), ctx)
    }
}
