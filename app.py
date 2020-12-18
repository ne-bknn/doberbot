import dash
import dash_core_components as dcc
import dash_html_components as html
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import textwrap

from main import main

external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css']

app = dash.Dash(__name__, external_stylesheets=external_stylesheets)

embedded, texts = main()

texts = [l[0] for l in texts]
texts = ["\n".join(textwrap.wrap(l, width=70)) for l in texts]
texts = [l.replace("\n", "<br>") for l in texts]

fig = go.Figure()
fig.add_trace(go.Scatter3d(x=embedded[:,0], y=embedded[:,1], z=embedded[:,2], mode='markers', hovertext=texts, hoverinfo="text"))

app.layout = html.Div(children=[
    html.H1(children='Doberbot'),

    html.Div(children='''
                      Trying to make sense out of traffic
    '''),
    
    html.Div([
    dcc.Graph(
        id='packet_space',
        figure=fig,
    ),
    ], style={"height": "1200px", "width": "1200px", "textAlign": "center"})
])

if __name__ == '__main__':
    app.run_server(debug=True)
