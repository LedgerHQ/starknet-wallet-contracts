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
async def test_registry(account_factory):
    account, registryOwnerAccount, dapp1, dapp2, registry, session_key_class = account_factory

    #await account1.initialize(StarkSigner_plugin_class_hash, [1, signer.public_key]).execute()
    registryId = 0
    await registry.createRegistry(registryId, registryOwner.public_key).execute()
    await registry.addDapp(registryId, dapp1.contract_address).execute()
    
    #toggleRegistry
    #await signer.send_transactions(account, [(dapp1.contract_address, 'toggleRegistry', [registryId, session_key_class])])
    
    # execution_info = await signer.send_transactions(account, [
    #     (registry.contract_address, 'checkAuthorisation', [registryId, dapp1.contract_address, session_key_class])
    # ])
    execution_info = await registry.checkAuthorisation(registryId, account.contract_address, dapp1.contract_address, session_key_class).call()




