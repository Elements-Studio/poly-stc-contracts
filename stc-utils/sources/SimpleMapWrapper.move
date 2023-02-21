module Bridge::SimpleMapWrapper {

    use StarcoinFramework::SimpleMap::{Self, SimpleMap};
    //
    // /// Acquire an immutable reference to the value which `key` maps to.
    // /// Returns specified default value if there is no entry for `key`.
    // public fun borrow_with_default<K: store + copy + drop, V: store>(table: &SimpleMap<K, V>, key: K, default: &V): &V {
    //     // if (!SimpleMap::contains_key(table, &(copy key))) {
    //     //     default
    //     // } else {
    //     //     SimpleMap::borrow(table, &(copy key))
    //     // }
    //     SimpleMap::borrow(table, &key)
    // }

    /// Acquire a mutable reference to the value which `key` maps to.
    /// Insert the pair (`key`, `default`) first if there is no entry for `key`.
    public fun borrow_mut_with_default<K: store + copy + drop, V: store + drop>(
        table: &mut SimpleMap<K, V>,
        key: K,
        default: V
    ): &mut V {
        if (!SimpleMap::contains_key(table, &key)) {
            SimpleMap::add(table, copy key, default)
        };
        SimpleMap::borrow_mut(table, &key)
    }

    /// Insert the pair (`key`, `value`) if there is no entry for `key`.
    /// update the value of the entry for `key` to `value` otherwise
    public fun upsert<K: store + copy + drop, V: store + drop>(table: &mut SimpleMap<K, V>, key: K, value: V) {
        if (!SimpleMap::contains_key(table, &key)) {
            SimpleMap::add(table, copy key, value)
        } else {
            let ref = SimpleMap::borrow_mut(table, &key);
            *ref = value;
        };
    }
}
