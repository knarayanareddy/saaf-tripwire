from fastapi import FastAPI, Depends
app = FastAPI()

def get_current_user():
    ...

@app.delete("/api/items/{item_id}")
def delete_item(item_id: str, user=Depends(get_current_user)):
    ITEMS.pop(item_id)
