import pytest
import asyncio
from utils.signers import MockSigner, MockSchnorrSigner
from utils.utils import assert_revert, get_contract_class, cached_contract, TRUE, State
from starkware.starknet.compiler.compile import get_selector_from_name


signer = MockSigner(123456789987654321)
other = MockSigner(987654321123456789)
schnorrSigner = MockSchnorrSigner([
    2523845276430757028405734299752039490663013462432225089608404049947463046225,
    1576448449201733381605048531123859424271649298253787562369801966884966169831,
    340766814953476881753430326832683665209763390437986951091619753285043833992,
    856801525844480644080312110652169615994257454289215590830299528998228012186
], 3067118560697589524435384931491320927549001107642126949141615071965375409500)

IACCOUNT_ID = 0xa66bd575


@pytest.fixture(scope='module')
def event_loop():
    return asyncio.new_event_loop()

@pytest.fixture(scope='module')
def contract_classes():
    account_cls = get_contract_class('Account')
    init_cls = get_contract_class("Initializable")
    attacker_cls = get_contract_class("AccountReentrancy")
    ECDSA_plugin_cls = get_contract_class("StarkSigner")
    Schnorr_cls = get_contract_class("Schnorr")

    return account_cls, init_cls, attacker_cls, ECDSA_plugin_cls, Schnorr_cls


@pytest.fixture(scope='module')
async def account_init(contract_classes):
    account_cls, init_cls, attacker_cls, ECDSA_plugin_cls, Schnorr_cls = contract_classes
    starknet = await State.init()

    account1 = await starknet.deploy(
        contract_class=account_cls,
        constructor_calldata=[],
        contract_address_salt=0
    )
    account2 = await starknet.deploy(
        contract_class=account_cls,
        constructor_calldata=[]
    )
    initializable1 = await starknet.deploy(
        contract_class=init_cls,
        constructor_calldata=[],
        contract_address_salt=1
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
    Schnorr_class = await starknet.declare(contract_class=Schnorr_cls)
    stark_signer_class_hash = ECDSA_plugin_class.class_hash
    Schnorr_class_hash = Schnorr_class.class_hash

    await account1.initialize(stark_signer_class_hash, [1, signer.public_key]).execute()
    await account2.initialize(stark_signer_class_hash, [1, signer.public_key]).execute()
    return starknet.state, account1, account2, initializable1, initializable2, attacker, stark_signer_class_hash, Schnorr_class_hash


@pytest.fixture
def account_factory(contract_classes, account_init):
    account_cls, init_cls, attacker_cls, ECDSA_plugin_cls, Schnorr_cls = contract_classes
    state, account1, account2, initializable1, initializable2, attacker, stark_signer_class_hash, Schnorr_class_hash = account_init
    _state = state.copy()
    account1 = cached_contract(_state, account_cls, account1)
    account2 = cached_contract(_state, account_cls, account2)
    initializable1 = cached_contract(_state, init_cls, initializable1)
    initializable2 = cached_contract(_state, init_cls, initializable2)
    attacker = cached_contract(_state, attacker_cls, attacker)

    return stark_signer_class_hash, account1, account2, initializable1, initializable2, attacker, Schnorr_class_hash


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
    ECDSA_plugin_class, account, _, initializable_1, initializable_2, *_ = account_factory

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
    _, account, _, _, _, attacker, _ = account_factory

    await assert_revert(
        signer.send_transaction(account, attacker.contract_address, 'account_takeover', []),
        reverted_with="Account: reentrant call"
    )

@pytest.mark.asyncio
async def test_public_key_setter(account_factory):
    ECDSA_plugin_class, account, *_ = account_factory

    execution_info = await account.readOnPlugin(ECDSA_plugin_class, get_selector_from_name('getPublicKey'), []).call()
    assert execution_info.result.retdata == [signer.public_key]

    # set new pubkey
    await signer.send_transactions(account, [(account.contract_address, 'executeOnPlugin', [ECDSA_plugin_class, get_selector_from_name('setPublicKey'), 1 ,other.public_key])])

    execution_info = await account.readOnPlugin(ECDSA_plugin_class, get_selector_from_name('getPublicKey'), []).call()
    assert execution_info.result.retdata == [other.public_key]

    await assert_revert(
        signer.send_transactions(account, [(account.contract_address, 'executeOnPlugin', [ECDSA_plugin_class, get_selector_from_name('setPublicKey'), 1 ,other.public_key])])
    )

@pytest.mark.asyncio
async def test_schnorr(account_factory):
    _, account, _, initializable_1, _, _, Schnorr_class_hash = account_factory

    execution_info = await initializable_1.initialized().call()
    assert execution_info.result == (0,)

    await signer.send_transactions(account, [(account.contract_address, 'addPlugin', [Schnorr_class_hash])])
    
    keyAgg = 3067118560697589524435384931491320927549001107642126949141615071965375409500

    await signer.send_transactions(account, [(account.contract_address, 'executeOnPlugin', [Schnorr_class_hash, get_selector_from_name('initialize'), 1 ,keyAgg])])

    await schnorrSigner.send_transactions(account,
        Schnorr_class_hash,
        [
            (initializable_1.contract_address, 'initialize', [])
        ]
    )

    execution_info = await initializable_1.initialized().call()
    assert execution_info.result == (1,)

