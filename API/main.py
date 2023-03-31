from fastapi import FastAPI
from pydantic import BaseModel
from Cryptographys import crypting
from typing import Dict, List, NewType
import os 
import json 

def init_app():
  """Initializes the app object and adds the router to it
  """
  app = FastAPI()
  return app

if __name__ == "__main__":
    app = init_app()

data_format = NewType(
    "User_data", List[Dict[str, any]
])
items_db : data_format = []
number_of_latest : int = 10
margin : int = 5
json_name  =  "\DataBase"
json_path = "C:\\Users\\Elep13\\Desktop\\sco\\API\\DataBase.json" 
public_key = "C:\\Users\\Elep13\\Desktop\\sco\\API\\keys\\public.pem" 

class Item(BaseModel):
    name: str
    description: str | None = None
    price: float
    tax: float | None = None

def callDataBase(mode: str, data : data_format = None):
    with open(json_path, mode) as f:
        if mode == "w":
            data = json.dumps(data, indent=4).encode('utf-8')
            content = crypting.encrypt(data, publicKeyFile=public_key)
            f.write(
                content
            )
        if mode == "r":
            read_file = f.read()
            if read_file == "":
                return False

            else:
                jsonObject = json.loads(read_file)
                return jsonObject

@app.get("/")
async def root():
    return {
        "Welcome_Message": "Welcome to the the PLC remote Server, go to '/docs' page to learn more about the API"
    }

@app.get("/items")
async def get_items(
    index: int = None, 
    item_id: int = None, 
    scroll: bool =  False
) -> list | None:

    filter_elements = []
    data = callDataBase("r")
    len_data = len(data) - 1

    if not data:
        return {
            "Message" : "No data available"
        }

    if item_id is not None:
        for item in data:
            if item.get("item_id") == item_id:
                filter_elements.append(item)

            if index is not None:
                message = {
                    "Message": f"Just item_id: {item_id} is return, instead of index: {index}",
                    "Data" : filter_elements
                }
                return message
            
            else:
                return filter_elements 

    if index is not None: 
        if scroll:
            return data[index:]
        
        if index > len_data:
            message = {
                "Message": f"Index: {index}, out of range"
            }
            return message
        
        filter_elements.append(data[index])
        return filter_elements
        
    return data


@app.post("/items/{item_id}")
async def create_item(item_id: int, item: Item, notes : str = None, latest : int = 5) -> list:

    result_post = {"item_id": item_id, **item.dict()}

    if notes is not None:
        result_post.update({"notes": notes})

    data = callDataBase("r")
    
    if not data:
        data = []
        data.append(result_post
        ) 
        callDataBase("w", data)
        return data
    
    else:
        data.append(result_post)
        len_items_db = len(data) - 1 
        data[len_items_db].update({"index": len_items_db})
        callDataBase("w", data)

        if len(data) > latest:
            index_latest = len_items_db - latest
            return data[index_latest:]
        else:
            return data
    

@app.put("/items")
async def update_item(item: Item, index: int, item_id: int | None = None, notes: str | None = None):
    data_content = callDataBase("r")
    len_data = len(data_content)
    
    if len_data >= index:
        try:
            result_post = {
                "item_id" : data_content[index]["item_id"],
                **item.dict()
            }
            if item_id is not None:
                result_post["item_id"] = item_id
            
            if notes is not None:
                result_post.update({"notes": notes})

            data_content[index] = result_post

            callDataBase("w", data_content)
        except Exception as e:
            return {
                "Error Message" : e
            } 

    return data_content[index]