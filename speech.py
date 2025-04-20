import pygame
from gtts import gTTS

def speak_alert(message):
    """ Converts text to speech and plays the audio in Pydroid """
    tts = gTTS(text=message, lang='en')
    tts.save("welcome.mp3")  # Save as an audio file
    
    # Initialize pygame mixer and play the audio
    pygame.mixer.init()
    pygame.mixer.music.load("welcome.mp3")
    pygame.mixer.music.play()
    
    # Wait until the speech finishes playing
    while pygame.mixer.music.get_busy():
        continue  

speak_alert("Welcome! To T-Give")