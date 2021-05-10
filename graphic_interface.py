import arcade

class MyGame(arcade.Window):
    """ Main application class. """

    def __init__(self, width, height):

        super().__init__(width, height)
        arcade.set_background_color(arcade.color.AMAZON)

    def setup(self):
        # Set up your game here
        pass
        

    def on_draw(self):
        """ Render the screen. """
        pass

    def update(self, delta_time):
        """ All the logic to move, and the game logic goes here """
        pass

def main():
    game = MyGame(SCREEN_WIDTH, SCREEN_HEIGHT)
    game.setup()
    arcade.run()


if __name__ == "__main__":
    main()
    