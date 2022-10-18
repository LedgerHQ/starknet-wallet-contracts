import pytest
import asyncio
import logging
from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.definitions.general_config import StarknetChainId
from starkware.starknet.business_logic.state.state import BlockInfo
from utils.signers import MockSigner, PluginSigner
from starkware.cairo.common.hash_state import compute_hash_on_elements
from starkware.starknet.compiler.compile import get_selector_from_name
from utils.merkle_utils import generate_merkle_proof, generate_merkle_root, get_leaves
from utils.utils import assert_revert, get_contract_class, str_to_felt, cached_contract, assert_event_emitted, TRUE, FALSE

LOGGER = logging.getLogger(__name__)

# H('StarkNetDomain(chainId:felt)')
STARKNET_DOMAIN_TYPE_HASH = 0x13cda234a04d66db62c06b8e3ad5f91bd0c67286c2c7519a826cf49da6ba478
# H('Session(key:felt,expires:felt,root:merkletree)')
SESSION_TYPE_HASH = 0x1aa0e1c56b45cf06a54534fa1707c54e520b842feb21d03b7deddb6f1e340c
# H(Policy(contractAddress:felt,selector:selector))
POLICY_TYPE_HASH = 0x2f0026e78543f036f33e26a8f5891b88c58dc1e20cbbfaf0bb53274da6fa568

signer = MockSigner(123456789987654321)
registryOwner = MockSigner(123456789987654321)

session_key = PluginSigner(666666666666666666)
wrong_session_key = MockSigner(6767676767)

DEFAULT_TIMESTAMP = 1640991600

@pytest.fixture(scope='module')
def event_loop():
    return asyncio.new_event_loop()

@pytest.fixture(scope='module')
async def get_starknet():
    starknet = await Starknet.empty()
    return starknet

def update_starknet_block(starknet, block_number=1, block_timestamp=DEFAULT_TIMESTAMP):
    starknet.state.state.block_info = BlockInfo(
        block_number=block_number,
        block_timestamp=block_timestamp,
        gas_price=0,
        starknet_version="0.9.1",
        sequencer_address=starknet.state.state.block_info.sequencer_address)

def reset_starknet_block(starknet):
    update_starknet_block(starknet=starknet)

@pytest.fixture(scope='module')
def contract_classes():
    account_cls = get_contract_class('Account')
    dapp_cls = get_contract_class("Dapp")
    session_key_cls = get_contract_class("SessionKey")
    stark_signer_cls = get_contract_class("StarkSigner")
    registry_cls = get_contract_class("DappRegistry")

    return account_cls, dapp_cls, session_key_cls, stark_signer_cls, registry_cls


@pytest.fixture(scope='module')
async def account_init(contract_classes):
    account_cls, dapp_cls, session_key_cls, stark_signer_cls, registry_cls = contract_classes
    starknet = await Starknet.empty()

    session_key_class = await starknet.declare(contract_class=session_key_cls)
    session_key_class_hash = session_key_class.class_hash
    
    stark_signer_class = await starknet.declare(contract_class=stark_signer_cls)
    stark_signer_class_hash = stark_signer_class.class_hash

    account = await starknet.deploy(
        contract_class=account_cls,
        constructor_calldata=[]
    )
    registryOwnerAccount = await starknet.deploy(
        contract_class=account_cls,
        constructor_calldata=[]
    )
    dapp1 = await starknet.deploy(
        contract_class=dapp_cls,
        constructor_calldata=[],
    )
    dapp2 = await starknet.deploy(
        contract_class=dapp_cls,
        constructor_calldata=[],
    )
    registry = await starknet.deploy(
            contract_class=registry_cls,
            constructor_calldata=[],
        )

    await account.initialize(stark_signer_class_hash, [1, signer.public_key]).execute()
    await registryOwnerAccount.initialize(stark_signer_class_hash, [1, registryOwner.public_key]).execute()
    await signer.send_transactions(account, [(account.contract_address, 'addPlugin', [session_key_class_hash])])

    return starknet.state, account, registryOwnerAccount, dapp1, dapp2, registry, session_key_class_hash, stark_signer_class_hash


@pytest.fixture
def account_factory(contract_classes, account_init):
    account_cls, dapp_cls, session_key_cls, stark_signer_cls, registry_cls = contract_classes
    state, account, registryOwnerAccount, dapp1, dapp2, registry, session_key_class, stark_signer_class_hash = account_init
    _state = state.copy()
    account = cached_contract(_state, account_cls, account)
    registryOwnerAccount = cached_contract(_state, account_cls, registryOwnerAccount)
    dapp1 = cached_contract(_state, dapp_cls, dapp1)
    dapp2 = cached_contract(_state, dapp_cls, dapp2)
    registry = cached_contract(_state, registry_cls, registry)

    return account, registryOwnerAccount, dapp1, dapp2, registry, session_key_class


@pytest.mark.asyncio
async def test_registry(account_factory, get_starknet):
    account, registryOwnerAccount, dapp1, dapp2, registry, session_key_class = account_factory
    starknet = get_starknet

    #await account1.initialize(StarkSigner_plugin_class_hash, [1, signer.public_key]).execute()
    registryId = 0
    await registry.createRegistry(registryId, registryOwner.public_key).execute()

    # create session key
    await signer.send_transactions(account, [(account.contract_address, 'addPlugin', [session_key_class])])
    merkle_leaves = get_leaves(
        POLICY_TYPE_HASH,
        [dapp1.contract_address, dapp1.contract_address, dapp2.contract_address, dapp2.contract_address, dapp2.contract_address],
        [get_selector_from_name('set_balance'), get_selector_from_name('set_balance_double'), get_selector_from_name('set_balance'), get_selector_from_name('set_balance_double'), get_selector_from_name('set_balance_times3')]
    )    
    leaves = list(map(lambda x: x[0], merkle_leaves))
    root = generate_merkle_root(leaves)
    session_token = get_session_token(session_key.public_key, DEFAULT_TIMESTAMP + 10, root, StarknetChainId.TESTNET.value, account.contract_address)

    proof = generate_merkle_proof(leaves, 0)
    
    await signer.send_transactions(account, [(account.contract_address, 'updateRegistry', [registry.contract_address, registryId])])
    
    execution_info = await registry.checkAuthorisation(registryId, dapp1.contract_address, session_key_class).call()
    assert ( execution_info.result == (FALSE,) )

    await assert_revert(
        session_key.send_transactions(account,
        session_key_class,
        [session_key.public_key, DEFAULT_TIMESTAMP + 10, session_token[0], session_token[1], root, len(proof), 1, *proof],
            [
                (dapp1.contract_address, 'set_balance', [47])
            ]),
        reverted_with="Account: not allowed by registry"
    )

    # add dapp with correct plugin to access the dapp
    await registry.addDapp(registryId, dapp1.contract_address, session_key_class).execute()

    execution_info = await registry.checkAuthorisation(registryId, dapp1.contract_address, session_key_class).call()
    assert ( execution_info.result == (TRUE,) )

    assert (await dapp1.get_balance().call()).result.res == 0
    update_starknet_block(starknet=starknet, block_timestamp=(DEFAULT_TIMESTAMP))

    tx_exec_info = await session_key.send_transactions(account,
        session_key_class,
        [session_key.public_key, DEFAULT_TIMESTAMP + 10, session_token[0], session_token[1], root, len(proof), 1, *proof], 
        [
            (dapp1.contract_address, 'set_balance', [47])
        ])

    assert_event_emitted(
        tx_exec_info,
        from_address=account.contract_address,
        name='transaction_executed',
        data=[]
    )

    # check it worked
    assert (await dapp1.get_balance().call()).result.res == 47

    



def get_session_token(session_key, session_expires, root, chain_id, account):

    domain_hash = compute_hash_on_elements([STARKNET_DOMAIN_TYPE_HASH, chain_id])
    message_hash = compute_hash_on_elements([SESSION_TYPE_HASH, session_key, session_expires, root])
    
    hash = compute_hash_on_elements([
        str_to_felt('StarkNet Message'),
        domain_hash,
        account,
        message_hash
    ])
    return signer.sign(hash)