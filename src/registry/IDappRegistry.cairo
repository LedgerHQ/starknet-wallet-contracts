
%lang starknet

@contract_interface
namespace IDappRegistry {

    func checkAuthorisation(
        registry_id: felt, dapp_address: felt, plugin_id: felt
    ) -> (isValid: felt) {
    }

}