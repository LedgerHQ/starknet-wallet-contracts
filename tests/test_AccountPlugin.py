import pytest
import asyncio
from utils.signers import MockSigner
from utils.utils import assert_revert, get_contract_class, cached_contract, TRUE, State
from starkware.starknet.compiler.compile import get_selector_from_name


signer = MockSigner(123456789987654321)
other = MockSigner(987654321123456789)

IACCOUNT_ID = 0xa66bd575


@pytest.fixture(scope='module')
def event_loop():
    return asyncio.new_event_loop()

@pytest.fixture(scope='module')
def contract_classes():
    account_cls = get_contract_class('AccountPlugin')
    init_cls = get_contract_class("Initializable")
    attacker_cls = get_contract_class("AccountReentrancy")
    ECDSA_plugin_cls = get_contract_class("ECDSABasePlugin")

    return account_cls, init_cls, attacker_cls, ECDSA_plugin_cls


@pytest.fixture(scope='module')
async def account_init(contract_classes):
    account_cls, init_cls, attacker_cls, ECDSA_plugin_cls = contract_classes
    starknet = await State.init()

    account1 = await starknet.deploy(
        contract_class=account_cls,
        constructor_calldata=[]
    )
    account2 = await starknet.deploy(
        contract_class=account_cls,
        constructor_calldata=[]
    )
    initializable1 = await starknet.deploy(
        contract_class=init_cls,
        constructor_calldata=[],
    )
    initializable2 = await starknet.deploy(
        contract_class=init_cls,
        constructor_calldata=[],
    )
    attacker = await starknet.deploy(
        contract_class=attacker_cls,
        constructor_calldata=[],
    )
    ECDSA_plugin_class = await starknet.declare(contract_class=ECDSA_plugin_cls)
    ECDSA_plugin_class_hash = ECDSA_plugin_class.class_hash

    await account1.initialize(ECDSA_plugin_class_hash, [signer.public_key]).execute()
    await account2.initialize(ECDSA_plugin_class_hash, [signer.public_key]).execute()
    return starknet.state, account1, account2, initializable1, initializable2, attacker, ECDSA_plugin_class_hash


@pytest.fixture
def account_factory(contract_classes, account_init):
    account_cls, init_cls, attacker_cls, ECDSA_plugin_cls = contract_classes
    state, account1, account2, initializable1, initializable2, attacker, ECDSA_plugin_class_hash = account_init
    _state = state.copy()
    account1 = cached_contract(_state, account_cls, account1)
    account2 = cached_contract(_state, account_cls, account2)
    initializable1 = cached_contract(_state, init_cls, initializable1)
    initializable2 = cached_contract(_state, init_cls, initializable2)
    attacker = cached_contract(_state, attacker_cls, attacker)

    return ECDSA_plugin_class_hash, account1, account2, initializable1, initializable2, attacker


@pytest.mark.asyncio
async def test_constructor(account_factory):
    ECDSA_plugin_class, account, *_ = account_factory
    
    assert (await account.isPlugin(ECDSA_plugin_class).call()).result.success == (1)


@pytest.mark.asyncio
async def test_execute(account_factory):
    _, account, _, initializable, *_ = account_factory

    execution_info = await initializable.initialized().call()
    assert execution_info.result == (0,)

    await signer.send_transactions(account, [(initializable.contract_address, 'initialize', [])])

    execution_info = await initializable.initialized().call()
    assert execution_info.result == (1,)


@pytest.mark.asyncio
async def test_multicall(account_factory):
    ECDSA_plugin_class, account, _, initializable_1, initializable_2, _ = account_factory

    execution_info = await initializable_1.initialized().call()
    assert execution_info.result == (0,)
    execution_info = await initializable_2.initialized().call()
    assert execution_info.result == (0,)

    await signer.send_transactions(
        account,
        [
            (initializable_1.contract_address, 'initialize', []),
            (initializable_2.contract_address, 'initialize', [])
        ]
    )

    execution_info = await initializable_1.initialized().call()
    assert execution_info.result == (1,)
    execution_info = await initializable_2.initialized().call()
    assert execution_info.result == (1,)

    # Should revert if trying to do call the plugins in a multicall
    await assert_revert(
        signer.send_transactions(
            account,
            [
                (initializable_1.contract_address, 'initialize', []),
                (initializable_2.contract_address, 'initialize', []),
                (account.contract_address, 'executeOnPlugin', 
                    [ECDSA_plugin_class, get_selector_from_name('setPublicKey'), 1 ,other.public_key]
                )
            ]
        )
    )

@pytest.mark.asyncio
async def test_account_takeover_with_reentrant_call(account_factory):
    _, account, _, _, _, attacker = account_factory

    await assert_revert(
        signer.send_transaction(account, attacker.contract_address, 'account_takeover', []),
        reverted_with="Account: no reentrant call"
    )

@pytest.mark.asyncio
async def test_public_key_setter(account_factory):
    ECDSA_plugin_class, account, *_ = account_factory

    execution_info = await account.readOnPlugin(ECDSA_plugin_class, get_selector_from_name('getSigner'), []).call()
    assert execution_info.result.retdata == [signer.public_key]

    # set new pubkey
    await signer.send_transactions(account, [(account.contract_address, 'executeOnPlugin', [ECDSA_plugin_class, get_selector_from_name('setPublicKey'), 1 ,other.public_key])])

    execution_info = await account.readOnPlugin(ECDSA_plugin_class, get_selector_from_name('getSigner'), []).call()
    assert execution_info.result.retdata == [other.public_key]

    await assert_revert(
        signer.send_transactions(account, [(account.contract_address, 'executeOnPlugin', [ECDSA_plugin_class, get_selector_from_name('setPublicKey'), 1 ,other.public_key])])
    )