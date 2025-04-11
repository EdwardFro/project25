require 'sinatra'
require 'slim'
require 'sqlite3'
require 'sinatra/reloader'
require 'bcrypt'

enable :session


def db_connection
  SQLite3::Database.new('db/SF6Frame.db')
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
  result = db.get_first_row("SELECT id, pwd_digest FROM users WHERE user = ?", username)

  if result && BCrypt::Password.new(result["pwd_digest"]) == password
    session[:user_id] = result["id"]
    redirect('/')
  else
    redirect('/error_l')
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
  existing = db.get_first_row("SELECT id FROM users WHERE user = ?", username)

  if existing
    redirect('/login') # User exists
  elsif password != password_confirm
    redirect('/error_s') # Passwords don't match
  else
    digest = BCrypt::Password.create(password)
    db.execute("INSERT INTO users (user, pwd_digest) VALUES (?, ?)", [username, digest])
    redirect('/login')
  end
end

get('/error_s') do
  slim(:error_s)
end

get('/error_l') do
  slim(:error_l)
end