db.session.execute(text("ALTER TABLE about ADD COLUMN logo VARCHAR(255);"))
db.session.commit()

