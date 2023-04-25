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
    log = Log(message=msg)
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
    opposite_side = "SELL" if order.side == "BUY" else "BUY"
    
    # Get orders of opposite side and same currency
    opposite_orders = g.session.query(Order).\
                        filter_by(side=opposite_side).\
                        filter_by(pair=order.pair).\
                        filter(Order.filled == False).\
                        order_by(Order.price.asc()).all()
    
    # Check if there are any opposite orders to fill
    if len(opposite_orders) == 0:
        return
    
    # Check if there is enough funds to fill the order
    opposite_order = opposite_orders[0]
    if opposite_order.price > order.price:
        return
    if opposite_order.amount > order.amount:
        return
    
    # Check if the opposite order is backed by a transaction
    opposite_tx = g.session.query(TX).filter_by(order_id=opposite_order.id).first()
    if not opposite_tx:
        return
    
    # Check if the current order is backed by a transaction
    current_tx = g.session.query(TX).filter_by(order_id=order.id).first()
    if not current_tx:
        return
    
    # Check if the opposite order has been filled
    if opposite_order.filled:
        return
    
    # Check if the current order has been filled
    if order.filled:
        return
    
    # Mark both orders as filled
    opposite_order.filled = True
    order.filled = True
    
    # Create transactions to execute the trade
    amount = min(order.amount, opposite_order.amount)
    price = opposite_order.price
    
    tx1 = {
        "platform": order.platform,
        "receiver_pk": order.receiver_pk,
        "amount": amount,
        "order_id": order.id
    }
    
    tx2 = {
        "platform": opposite_order.platform,
        "receiver_pk": opposite_order.receiver_pk,
        "amount": amount,
        "order_id": opposite_order.id
    }
    
    # Append transactions to list of transactions
    txes.append(tx1)
    txes.append(tx2)
    
    # Subtract the traded amount from both orders
    order.amount -= amount
    opposite_order.amount -= amount
    
    # If either order is completely filled, mark it as such
    if order.amount == 0:
        order.filled = True
        
    if opposite_order.amount == 0:
        opposite_order.filled = True
    
    # Recursively call fill_order() until there are no more orders to fill
    fill_order(order, txes)
    
    return

  
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
            return jsonify( eth_pk )
        if content['platform'] == "Algorand":
            #Your code here
            algo_sk, algo_pk = get_algo_keys()
            return jsonify( algo_pk )

@app.route('/trade', methods=['POST'])
def trade():
    print("In trade endpoint")
    if request.method == "POST":
        content = request.get_json(silent=True)
        print( f"content = {json.dumps(content)}" )
        columns = [ "sender_pk", "receiver_pk", "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform" ]
        fields = [ "sig", "payload" ]

        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                print( json.dumps(content) )
                log_message(content)
                return jsonify( False )
        
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                print( json.dumps(content) )
                log_message(content)
                return jsonify( False )
            
        #Your code here
        #Note that you can access the database session using g.session

        # TODO: Check the signature
        sig = content['sig']
        payload = content['payload']
        platform = payload['platform']
        if platform == 'Algorand':
            if not verify_algo_signature(payload, sig, payload['sender_pk']):
                log_message(content)
                return jsonify(False)
        elif platform == 'Ethereum':
            if not verify_eth_signature(payload, sig, payload['sender_pk']):
                log_message(content)
                return jsonify(False)
        else:
            log_message(content)
            return jsonify(False)

        # TODO: Add the order to the database
        order = Order(sender_pk=payload['sender_pk'], receiver_pk=payload['receiver_pk'],
                      buy_currency=payload['buy_currency'], sell_currency=payload['sell_currency'],
                      buy_amount=payload['buy_amount'], sell_amount=payload['sell_amount'], signature=sig)
        g.session.add(order)
        g.session.commit()

        # TODO: Fill the order
        fill_order(order)

        # TODO: Be sure to return jsonify(True) or jsonify(False) depending on if the method was successful
        return jsonify(True)

@app.route('/order_book')
def order_book():
    fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk", "sender_pk" ]
    
    
    result = []
    for order in orders:
        result.append({'sender_pk': order.sender_pk,
                       'receiver_pk': order.receiver_pk,
                       'buy_currency': order.buy_currency,
                       'sell_currency': order.sell_currency,
                       'buy_amount': order.buy_amount,
                       'sell_amount': order.sell_amount,
                       'signature': order.signature})

    return jsonify({'data': result})

if __name__ == '__main__':
    app.run(port='5002')
