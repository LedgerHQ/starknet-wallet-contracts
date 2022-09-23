import pytest
import asyncio
import logging
from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.business_logic.state.state import BlockInfo
from utils.signers import MockSigner
from starkware.cairo.common.hash_state import compute_hash_on_elements
from starkware.starknet.compiler.compile import get_selector_from_name
from utils.merkle_utils import generate_merkle_proof, generate_merkle_root, get_leaves
from utils.utils import assert_revert, get_contract_class, cached_contract, assert_event_emitted


LOGGER = logging.getLogger(__name__)

signer = MockSigner(123456789987654321)

session_key = MockSigner(666666666666666666)
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
    account_cls = get_contract_class('AccountPlugin')
    dapp_cls = get_contract_class("Dapp")
    session_key_cls = get_contract_class("SessionKey")
    ECDSABasePlugin_cls = get_contract_class("ECDSABasePlugin")

    return account_cls, dapp_cls, session_key_cls, ECDSABasePlugin_cls


@pytest.fixture(scope='module')
async def account_init(contract_classes):
    account_cls, dapp_cls, session_key_cls, ECDSABasePlugin_cls = contract_classes
    starknet = await Starknet.empty()

    session_key_class = await starknet.declare(contract_class=session_key_cls)
    session_key_class_hash = session_key_class.class_hash
    
    base_plugin_class = await starknet.declare(contract_class=ECDSABasePlugin_cls)
    base_plugin_class_hash = base_plugin_class.class_hash

    account = await starknet.deploy(
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

    await account.initialize(base_plugin_class_hash, [signer.public_key]).execute()

    return starknet.state, account, dapp1, dapp2, session_key_class_hash, base_plugin_class_hash


@pytest.fixture
def account_factory(contract_classes, account_init):
    account_cls, dapp_cls, session_key_cls, ECDSABasePlugin_cls = contract_classes
    state, account, dapp1, dapp2, session_key_class, base_plugin_class_hash = account_init
    _state = state.copy()
    account = cached_contract(_state, account_cls, account)
    dapp1 = cached_contract(_state, dapp_cls, dapp1)
    dapp2 = cached_contract(_state, dapp_cls, dapp2)

    return account, dapp1, dapp2, session_key_class


@pytest.mark.asyncio
async def test_addPlugin(account_factory):
    account, _, _, session_key_class = account_factory

    assert (await account.isPlugin(session_key_class).call()).result.success == (0)
    # await sender.send_transaction([(account.contract_address, 'addPlugin', [session_key_class])], [signer])
    await signer.send_transactions(account, [(account.contract_address, 'addPlugin', [session_key_class])])
    assert (await account.isPlugin(session_key_class).call()).result.success == (1)

@pytest.mark.asyncio
async def test_removePlugin(account_factory):
    account, _, _, session_key_class = account_factory

    assert (await account.isPlugin(session_key_class).call()).result.success == (0)
    await signer.send_transactions(account, [(account.contract_address, 'addPlugin', [session_key_class])])
    assert (await account.isPlugin(session_key_class).call()).result.success == (1)
    await signer.send_transactions(account, [(account.contract_address, 'removePlugin', [session_key_class])])
    assert (await account.isPlugin(session_key_class).call()).result.success == (0)

@pytest.mark.asyncio
async def test_call_dapp_with_session_key(account_factory, get_starknet):
    account, dapp1, dapp2, session_key_class = account_factory
    starknet = get_starknet

    # add session key plugin
    await signer.send_transactions(account, [(account.contract_address, 'addPlugin', [session_key_class])])
    # authorise session key
    merkle_leaves = get_leaves(
        [dapp1.contract_address, dapp1.contract_address, dapp2.contract_address, dapp2.contract_address, dapp2.contract_address],
        [get_selector_from_name('set_balance'), get_selector_from_name('set_balance_double'), get_selector_from_name('set_balance'), get_selector_from_name('set_balance_double'), get_selector_from_name('set_balance_times3')]
    )    
    leaves = list(map(lambda x: x[0], merkle_leaves))
    root = generate_merkle_root(leaves)
    session_token = get_session_token(session_key.public_key, DEFAULT_TIMESTAMP + 10, root)

    proof = generate_merkle_proof(leaves, 0)
    proof2 = generate_merkle_proof(leaves, 4)
    
    assert (await dapp1.get_balance().call()).result.res == 0
    update_starknet_block(starknet=starknet, block_timestamp=(DEFAULT_TIMESTAMP))
    # call with session key
    # passing once the len(proof). if odd nb of leaves proof will be filled with 0.
    tx_exec_info = await session_key.send_transactions(account, 
        [
            (account.contract_address, 'use_plugin', [session_key_class, session_key.public_key, DEFAULT_TIMESTAMP + 10, session_token[0], session_token[1], root, len(proof), *proof, *proof2]),
            (dapp1.contract_address, 'set_balance', [47]),
            (dapp2.contract_address, 'set_balance_times3', [20])
        ])

    assert_event_emitted(
        tx_exec_info,
        from_address=account.contract_address,
        name='transaction_executed',
        data=[]
    )
    # check it worked
    assert (await dapp1.get_balance().call()).result.res == 47
    assert (await dapp2.get_balance().call()).result.res == 60

    # wrong policy call with random proof
    await assert_revert(
        session_key.send_transactions(account,
            [
                (account.contract_address, 'use_plugin', [session_key_class, session_key.public_key, DEFAULT_TIMESTAMP + 10, session_token[0], session_token[1], root, len(proof), *proof]),
                (dapp1.contract_address, 'set_balance_times3', [47])
            ]),
        reverted_with="Not allowed by policy"
    )

    # revoke session key
    tx_exec_info = await signer.send_transactions(account, [(account.contract_address, 'executeOnPlugin', [session_key_class, get_selector_from_name('revoke_session_key'), 1, session_key.public_key])])
    assert_event_emitted(
        tx_exec_info,
        from_address=account.contract_address,
        name='session_key_revoked',
        data=[session_key.public_key]
    )
    # check the session key is no longer authorised
    await assert_revert(
        session_key.send_transactions(account,
            [
                (account.contract_address, 'use_plugin', [session_key_class, session_key.public_key, DEFAULT_TIMESTAMP + 10, session_token[0], session_token[1], root, len(proof), *proof]),
                (dapp1.contract_address, 'set_balance', [47])
            ]),
        reverted_with="session key revoked"
    )

def get_session_token(key, expires, root):
    session = [
        key,
        expires,
        root
    ]
    hash = compute_hash_on_elements(session)
    return signer.sign(hash)