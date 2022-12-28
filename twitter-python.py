import tweepy
print("Test")
#Installation / Access to Twitter Account

consumer_key = 'jlZUrZzRqxwLZjZt09Jpc3kVJ'
consumer_secret = 'PZQefIld1R0mqJGOS468AaRpSuYU8jaRY7LifRjyW82ig2dZsb'
access_token = '3253920115-R8BZu2LP81X6uZ8aUDpG3E3lxmGPypM46hCxZKw'
access_token_secret = 'IbeDrT7hyzhtjqEeSLlh8v4eiZXKmK93xtZvMZg2lsWXD'

auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
auth.set_access_token(access_token, access_token_secret)
api = tweepy.API(auth, wait_on_rate_limit = True)

def extract_messages(count):
    messages = []
    all_data = api.get_direct_messages(count = count)
    for i in range(len(all_data)):
        text = all_data[i]._json['message_create']['message_data']['text']
        messages.append(text)
    return messages

print(extract_messages(1234))
