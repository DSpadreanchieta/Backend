const express = require('express');
const app = express();
app.get('/produtos', (req, res) => {
const produtos = [
{ id: 1, nome: 'Camiseta', preco: 29.99 },
{ id: 2, nome: 'Calça Jeans', preco: 89.99 },
{ id: 3, nome: 'Tênis', preco: 119.99 }
];
res.json(produtos);
});
const port = 3000;
app.listen(port, () => {
console.log(`API rodando em http://localhost:${port}/produtos`);
});

