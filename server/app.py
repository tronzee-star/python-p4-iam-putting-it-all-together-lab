#!/usr/bin/env python3

from flask import request, session, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe


class Signup(Resource):
    def post(self):
        data = request.get_json()

        try:
            new_user = User(
                username=data.get("username"),
                bio=data.get("bio"),
                image_url=data.get("image_url"),
            )
            new_user.password_hash = data.get("password")

            db.session.add(new_user)
            db.session.commit()

            session["user_id"] = new_user.id

            return make_response(new_user.to_dict(), 201)

        except (ValueError, IntegrityError) as e:
            db.session.rollback()
            return make_response({"error": str(e)}, 422)


class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")
        if user_id:
            user = User.query.get(user_id)
            if user:
                return make_response(user.to_dict(), 200)
        return make_response({"error": "Unauthorized"}, 401)


class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(username=data.get("username")).first()

        if user and user.authenticate(data.get("password")):
            session["user_id"] = user.id
            return make_response(user.to_dict(), 200)

        return make_response({"error": "Unauthorized"}, 401)


class Logout(Resource):
    def delete(self):
        if session.get("user_id"):
            session["user_id"] = None
            return make_response({}, 204)
        return make_response({"error": "Unauthorized"}, 401)


class RecipeIndex(Resource):
    def get(self):
        user_id = session.get("user_id")
        if not user_id:
            return make_response({"error": "Unauthorized"}, 401)

        user = User.query.get(user_id)
        if not user:
            return make_response({"error": "Unauthorized"}, 401)

        recipes = [recipe.to_dict() for recipe in user.recipes]
        return make_response(recipes, 200)

    def post(self):
        user_id = session.get("user_id")
        if not user_id:
            return make_response({"error": "Unauthorized"}, 401)

        data = request.get_json()
        try:
            new_recipe = Recipe(
                title=data.get("title"),
                instructions=data.get("instructions"),
                minutes_to_complete=data.get("minutes_to_complete"),
                user_id=user_id,
            )
            db.session.add(new_recipe)
            db.session.commit()

            return make_response(new_recipe.to_dict(), 201)

        except ValueError as e:
            db.session.rollback()
            return make_response({"error": str(e)}, 422)


api.add_resource(Signup, "/signup", endpoint="signup")
api.add_resource(CheckSession, "/check_session", endpoint="check_session")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(Logout, "/logout", endpoint="logout")
api.add_resource(RecipeIndex, "/recipes", endpoint="recipes")


if __name__ == "__main__":
    app.run(port=5555, debug=True)
