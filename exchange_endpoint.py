from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

""" Pre-defined methods (do not need to change) """

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()

def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True
    
    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()
    
    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True
    
    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

        
    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True
    
    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()
        
""" End of pre-defined methods """
        
""" Helper Methods (skeleton code for you to implement) """

def log_message(message_dict):
    msg = json.dumps(message_dict)

    # TODO: Add message to the Log table
    # Add message to the Log table
    log = Log(message=json.dumps(message_dict))
    g.session.add(log)
    g.session.commit()
    return

def get_algo_keys():
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the algorand public/private keys
    try:
        with open("algo_keys.json", "r") as f:
            keys = json.load(f)
            algo_sk = keys['private_key']
            algo_pk = keys['public_key']
    except:
        algo_sk, algo_pk = algosdk.account.generate_account()
        with open("algo_keys.json", "w") as f:
            json.dump({'private_key': algo_sk, 'public_key': algo_pk}, f)
    
    return algo_sk, algo_pk


def get_eth_keys(filename = "eth_mnemonic.txt"):
    w3 = Web3()
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys
    try:
        with open("eth_keys.json", "r") as f:
            keys = json.load(f)
            eth_sk = keys['private_key']
            eth_pk = keys['public_key']
    except:
        with open(filename, "r") as f:
            mnemonic = f.read()
        account = eth_account.Account.from_mnemonic(mnemonic.strip())
        eth_sk = account.key.hex()
        eth_pk = Web3.toChecksumAddress(account.address)
        with open("eth_keys.json", "w") as f:
            json.dump({'private_key': eth_sk, 'public_key': eth_pk}, f)
    
    return eth_sk, eth_pk
  
def fill_order(order, txes=[]):
    # Get the opposite side of the order
    #Your code here
    #if all(key in order for key in ['sender_pk','buy_amount','sell_amount', 'receiver_pk', 'buy_currency', 'sell_currency']):
        order_obj = order        
        #session.add(order_obj)
        #session.commit()
        print('Here!!!')
        for existing_order in g.session.query(Order).all():
            if order_obj.sell_amount * existing_order.sell_amount >= order_obj.buy_amount * existing_order.buy_amount and existing_order.buy_currency == order_obj.sell_currency and existing_order.sell_currency == order_obj.buy_currency and existing_order.filled == None:
                order_obj.filled = datetime.now()
                existing_order.filled = datetime.now()
                order_obj.counterparty_id = existing_order.id
                existing_order.counterparty_id = order_obj.id
                if order_obj.buy_amount>existing_order.sell_amount:
                    order_r = {}
                    order_r['filled'] = None
                    order_r['creator_id'] = order_obj.id
                    order_r['sender_pk'] = order_obj.sender_pk
                    order_r['receiver_pk'] = order_obj.receiver_pk
                    order_r['buy_currency'] = order_obj.buy_currency
                    order_r['sell_currency'] = order_obj.sell_currency
                    order_r['buy_amount'] = order_obj.buy_amount-existing_order.sell_amount
                    order_r['sell_amount'] = order_r['buy_amount'] * order_obj.sell_amount/order_obj.buy_amount
                    process_order(order_r)
                    order_r_obj = Order(**{f:order_r[f] for f in fields})
                    session.add(order_r_obj)
                    session.commit()
                    print('1:Child order added - 1')

                elif existing_order.buy_amount>order_obj.sell_amount:
                    order_r = {}
                    order_r['filled'] = None
                    order_r['creator_id'] = existing_order.id
                    order_r['sender_pk'] = existing_order.sender_pk
                    order_r['receiver_pk'] = existing_order.receiver_pk
                    order_r['buy_currency'] = existing_order.buy_currency
                    order_r['sell_currency'] = existing_order.sell_currency
                    order_r['buy_amount'] = existing_order.buy_amount-order_obj.sell_amount
                    order_r['sell_amount'] = order_r['buy_amount'] *existing_order.sell_amount/existing_order.buy_amount
                    #process_order(order_r)
                    order_r_obj = Order(**{f:order_r[f] for f in fields})
                    session.add(order_r_obj)
                    session.commit()
                    print('2:Child order added - 2')
                else:
                    print('5: Child order NOT created - 5')
                    #print(existing_order.buy_amount)
                    #print(order_obj.sell_amount)
                    #print(order_obj.buy_amount)
                    #print(existing_order.sell_amount)
                    #print('##########')

                break
            txes.append(order_obj)
            txes.append(existing_order)
            break
        return txes
  
def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print( f"Trying to execute {len(txes)} transactions" )
    print( f"IDs = {[tx['order_id'] for tx in txes]}" )
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    
    if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
        print( "Error: execute_txes got an invalid platform!" )
        print( tx['platform'] for tx in txes )

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table

    for tx in algo_txes:
        if send_tokens_algo(tx['receiver_pk'], algo_pk, algo_sk, tx['amount']):
            print(f"Algo transaction {tx['order_id']} successful")
            tx_row = TX(id=tx['order_id'], tx_hash="", platform="Algorand")
            g.session.add(tx_row)
        else:
            print(f"Algo transaction {tx['order_id']} failed")
            g.session.rollback()
            return False

    for tx in eth_txes:
        if send_tokens_eth(tx['receiver_pk'], eth_pk, eth_sk, tx['amount']):
            print(f"Ethereum transaction {tx['order_id']} successful")
            tx_row = TX(id=tx['order_id'], tx_hash="", platform="Ethereum")
            g.session.add(tx_row)
        else:
            print(f"Ethereum transaction {tx['order_id']} failed")
            g.session.rollback()
            return False

    g.session.commit()
    return True

""" End of Helper methods"""
  
@app.route('/address', methods=['POST'])
def address():
    print('Here')
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print( f"Error: no platform provided" )
            return jsonify( "Error: no platform provided" )
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print( f"Error: {content['platform']} is an invalid platform" )
            return jsonify( f"Error: invalid platform provided: {content['platform']}"  )
        
        if content['platform'] == "Ethereum":
            #Your code here
            eth_sk, eth_pk = get_eth_keys()
            print(eth_sk, eth_pk)
            return jsonify( eth_pk )
        if content['platform'] == "Algorand":
            #Your code here
            algo_sk, algo_pk = get_algo_keys()
            print(eth_sk, eth_pk)
            return jsonify( algo_sk, algo_pk )

@app.route('/trade', methods=['POST'])
def trade():
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
    get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        # Your code here
        
        # 1. Check the signature
        
        # 2. Add the order to the table
        
        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)

        # 3b. Fill the order (as in Exchange Server II) if the order is valid
        
        # 4. Execute the transactions
        
        # If all goes well, return jsonify(True). else return jsonify(False)
        return jsonify(True)

@app.route('/order_book')
def order_book():
    fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk", "sender_pk" ]
    
    # Same as before
    pass

if __name__ == '__main__':
    app.run(port='5002')
