require 'sinatra'
require 'slim'
require 'sqlite3'
require 'sinatra/reloader'
require 'bcrypt'

enable :sessions


def db_connection
  SQLite3::Database.new('db/SF6Frame.db')
end

def current_user
  return nil unless session[:user_id]
  db = db_connection
  db.results_as_hash = true
  db.get_first_row("SELECT * FROM users WHERE id = ?", session[:user_id])
end

def admin?
  @current_user && @current_user["role"] == "admin"
end


before do
  @current_user = current_user
end


get('/') do
  db = db_connection
  db.results_as_hash = true
  characters = db.execute('SELECT id, name FROM characters ORDER BY id ASC')
  slim(:start, locals: { characters: characters })
end

get('/character/:id') do
  db = db_connection
  db.results_as_hash = true
  character = db.get_first_row('SELECT * FROM characters WHERE id = ?', params[:id])
  moves = db.execute('SELECT * FROM moves WHERE character_id = ?', params[:id])
  slim(:character, locals: { character: character, moves: moves })
end

get('/login') do
  slim(:login)
end

post('/login') do
  username = params["username"]
  password = params["password"]

  db = db_connection
  db.results_as_hash = true
  user = db.get_first_row("SELECT id, pwd_digest FROM users WHERE user = ?", username)

  if user && BCrypt::Password.new(user["pwd_digest"]) == password
    session[:user_id] = user["id"]
    redirect('/')
  else
    redirect('/error')
  end
end

get('/logout') do
  session.clear
  redirect('/')
end

get('/signup') do
  slim(:signup)
end

post('/signup') do
  username = params["username"]
  password = params["password"]
  password_confirm = params["password_confirm"]

  db = db_connection
  db.results_as_hash = true
  existing_user = db.get_first_row("SELECT id FROM users WHERE user = ?", username)

  if existing_user
    redirect('/login') # användarnamn redan taget
  elsif password != password_confirm
    redirect('/error') # lösenorden matchar inte
  else
    digest = BCrypt::Password.create(password)
    db.execute("INSERT INTO users (user, pwd_digest) VALUES (?, ?)", [username, digest])
    
    # Logga in direkt efter registrering
    user_id = db.last_insert_row_id
    session[:user_id] = user_id

    redirect('/')
  end
end



get('/error') do
  slim(:error)
end


get('/saved_fighters') do
  redirect('/login') unless current_user
  
  db = db_connection
  db.results_as_hash = true

  characters = db.execute(
    'SELECT characters.id, characters.name 
     FROM characters
     JOIN saved_characters ON characters.id = saved_characters.character_id
     WHERE saved_characters.user_id = ?',
    session[:user_id]
  )

  slim(:saved_fighters, locals: { characters: characters })
end


post('/save_character') do
  redirect('/login') unless @current_user
  user_id = @current_user['id']
  character_id = params["character_id"]

  db = db_connection
  existing = db.get_first_row("SELECT * FROM saved_characters WHERE user_id = ? AND character_id = ?", [user_id, character_id])

  if existing
    db.execute("DELETE FROM saved_characters WHERE user_id = ? AND character_id = ?", [user_id, character_id])
  else
    db.execute("INSERT INTO saved_characters (user_id, character_id) VALUES (?, ?)", [user_id, character_id])
  end

  redirect("/character/#{character_id}")
end


post('/unsave_character/:id') do
  redirect('/login') unless current_user
  character_id = params["character_id"]
  db = db_connection
  db.execute("DELETE FROM saved_characters WHERE user_id = ? AND character_id = ?", [session[:user_id], character_id])
  redirect("/character/#{character_id}")
end

get('/edit_character/:id') do
  db = db_connection
  db.results_as_hash = true
  character = db.get_first_row('SELECT * FROM characters WHERE id = ?', params[:id])
  moves = db.execute('SELECT * FROM moves WHERE character_id = ?', params[:id])
  slim(:edit_character, locals: { character: character, moves: moves })
end

post('/update_character/:id') do
  description = params["description"]
  tier = params["tier"]
  input_type = params["input_type"]
  type = params["type"]

  db = db_connection
  db.execute("UPDATE characters SET description = ?, tier = ?, input_type = ?, type = ? WHERE id = ?", 
             [description, tier, input_type, type, params[:id]])

  redirect("/character/#{params[:id]}")
end

post('/update_move/:id') do
  db = db_connection

  db.execute("UPDATE moves SET numCmd = ?, dmg = ?, startup = ?, active = ?, recovery = ?, total = ?, onHit = ?, onBlock = ?
              WHERE id = ?", 
              [params["numCmd"], params["dmg"], params["startup"], params["active"], params["recovery"], params["total"], 
              params["onHit"], params["onBlock"], params[:id]])

  character_id = db.get_first_value("SELECT character_id FROM moves WHERE id = ?", params[:id])
  redirect("/edit_character/#{character_id}")
end






